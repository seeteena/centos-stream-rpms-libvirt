/*
 * virclosecallbacks.c: Connection close callbacks routines
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "viralloc.h"
#include "virclosecallbacks.h"
#include "virlog.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.closecallbacks");

typedef struct _virDriverCloseDef virDriverCloseDef;
struct _virDriverCloseDef {
    virConnectPtr conn;
    virCloseCallback cb;
};

struct _virCloseCallbacks {
    virObjectLockable parent;

    /* UUID string to qemuDriverCloseDef mapping */
    GHashTable *list;
};


static virClass *virCloseCallbacksClass;
static void virCloseCallbacksDispose(void *obj);

static int virCloseCallbacksOnceInit(void)
{
    if (!VIR_CLASS_NEW(virCloseCallbacks, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCloseCallbacks);


virCloseCallbacks *
virCloseCallbacksNew(void)
{
    virCloseCallbacks *closeCallbacks;

    if (virCloseCallbacksInitialize() < 0)
        return NULL;

    if (!(closeCallbacks = virObjectLockableNew(virCloseCallbacksClass)))
        return NULL;

    closeCallbacks->list = virHashNew(g_free);

    return closeCallbacks;
}

static void
virCloseCallbacksDispose(void *obj)
{
    virCloseCallbacks *closeCallbacks = obj;

    g_clear_pointer(&closeCallbacks->list, g_hash_table_unref);
}

int
virCloseCallbacksSet(virCloseCallbacks *closeCallbacks,
                     virDomainObj *vm,
                     virConnectPtr conn,
                     virCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDriverCloseDef *closeDef;
    int ret = -1;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p, cb=%p",
              vm->def->name, uuidstr, conn, cb);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (closeDef) {
        if (closeDef->conn != conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Close callback for domain %s already registered"
                             " with another connection %p"),
                           vm->def->name, closeDef->conn);
            goto cleanup;
        }
        if (closeDef->cb && closeDef->cb != cb) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Another close callback is already defined for"
                             " domain %s"), vm->def->name);
            goto cleanup;
        }

        closeDef->cb = cb;
    } else {
        closeDef = g_new0(virDriverCloseDef, 1);
        closeDef->conn = conn;
        closeDef->cb = cb;
        if (virHashAddEntry(closeCallbacks->list, uuidstr, closeDef) < 0) {
            VIR_FREE(closeDef);
            goto cleanup;
        }
        virObjectRef(vm);
    }

    virObjectRef(closeCallbacks);
    ret = 0;
 cleanup:
    virObjectUnlock(closeCallbacks);
    return ret;
}

int
virCloseCallbacksUnset(virCloseCallbacks *closeCallbacks,
                       virDomainObj *vm,
                       virCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDriverCloseDef *closeDef;
    int ret = -1;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, cb=%p",
              vm->def->name, uuidstr, cb);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (!closeDef)
        goto cleanup;

    if (closeDef->cb && closeDef->cb != cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Trying to remove mismatching close callback for"
                         " domain %s"), vm->def->name);
        goto cleanup;
    }

    if (virHashRemoveEntry(closeCallbacks->list, uuidstr) < 0)
        goto cleanup;

    virObjectUnref(vm);
    ret = 0;
 cleanup:
    virObjectUnlock(closeCallbacks);
    if (!ret)
        virObjectUnref(closeCallbacks);
    return ret;
}

virCloseCallback
virCloseCallbacksGet(virCloseCallbacks *closeCallbacks,
                     virDomainObj *vm,
                     virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDriverCloseDef *closeDef;
    virCloseCallback cb = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p",
              vm->def->name, uuidstr, conn);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (closeDef && (!conn || closeDef->conn == conn))
        cb = closeDef->cb;

    virObjectUnlock(closeCallbacks);

    VIR_DEBUG("cb=%p", cb);
    return cb;
}

virConnectPtr
virCloseCallbacksGetConn(virCloseCallbacks *closeCallbacks,
                         virDomainObj *vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDriverCloseDef *closeDef;
    virConnectPtr conn = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s", vm->def->name, uuidstr);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (closeDef)
        conn = closeDef->conn;

    virObjectUnlock(closeCallbacks);

    VIR_DEBUG("conn=%p", conn);
    return conn;
}


typedef struct _virCloseCallbacksListEntry virCloseCallbacksListEntry;
struct _virCloseCallbacksListEntry {
    unsigned char uuid[VIR_UUID_BUFLEN];
    virCloseCallback callback;
};

typedef struct _virCloseCallbacksList virCloseCallbacksList;
struct _virCloseCallbacksList {
    size_t nentries;
    virCloseCallbacksListEntry *entries;
};

struct virCloseCallbacksData {
    virConnectPtr conn;
    virCloseCallbacksList *list;
};

static int
virCloseCallbacksGetOne(void *payload,
                        const char *key,
                        void *opaque)
{
    struct virCloseCallbacksData *data = opaque;
    virDriverCloseDef *closeDef = payload;
    const char *uuidstr = key;
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDParse(uuidstr, uuid) < 0)
        return 0;

    VIR_DEBUG("conn=%p, thisconn=%p, uuid=%s, cb=%p",
              closeDef->conn, data->conn, uuidstr, closeDef->cb);

    if (data->conn != closeDef->conn || !closeDef->cb)
        return 0;

    VIR_EXPAND_N(data->list->entries, data->list->nentries, 1);

    memcpy(data->list->entries[data->list->nentries - 1].uuid,
           uuid, VIR_UUID_BUFLEN);
    data->list->entries[data->list->nentries - 1].callback = closeDef->cb;
    return 0;
}

static virCloseCallbacksList *
virCloseCallbacksGetForConn(virCloseCallbacks *closeCallbacks,
                            virConnectPtr conn)
{
    virCloseCallbacksList *list = NULL;
    struct virCloseCallbacksData data;

    list = g_new0(virCloseCallbacksList, 1);

    data.conn = conn;
    data.list = list;

    virHashForEach(closeCallbacks->list, virCloseCallbacksGetOne, &data);

    return list;
}


void
virCloseCallbacksRun(virCloseCallbacks *closeCallbacks,
                     virConnectPtr conn,
                     virDomainObjList *domains)
{
    virCloseCallbacksList *list;
    size_t i;

    VIR_DEBUG("conn=%p", conn);

    /* We must not hold the lock while running the callbacks,
     * so first we obtain the list of callbacks, then remove
     * them all from the hash. At that point we can release
     * the lock and run the callbacks safely. */

    virObjectLock(closeCallbacks);
    list = virCloseCallbacksGetForConn(closeCallbacks, conn);
    if (!list) {
        virObjectUnlock(closeCallbacks);
        return;
    }

    for (i = 0; i < list->nentries; i++) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(list->entries[i].uuid, uuidstr);
        virHashRemoveEntry(closeCallbacks->list, uuidstr);
    }
    virObjectUnlock(closeCallbacks);

    for (i = 0; i < list->nentries; i++) {
        virDomainObj *vm;

        /* Grab a ref and lock to the vm */
        if (!(vm = virDomainObjListFindByUUID(domains,
                                              list->entries[i].uuid))) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(list->entries[i].uuid, uuidstr);
            VIR_DEBUG("No domain object with UUID %s", uuidstr);
            continue;
        }

        /* Remove the ref taken out during virCloseCallbacksSet since
         * we're about to call the callback function and we have another
         * ref anyway (so it cannot be deleted).
         *
         * Call the callback function and end the API usage. */
        virObjectUnref(vm);
        list->entries[i].callback(vm, conn);
        virDomainObjEndAPI(&vm);
    }
    VIR_FREE(list->entries);
    VIR_FREE(list);
}
