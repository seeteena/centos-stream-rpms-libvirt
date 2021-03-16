# -*- rpm-spec -*-

# This spec file assumes you are building on a Fedora or RHEL version
# that's still supported by the vendor. It may work on other distros
# or versions, but no effort will be made to ensure that going forward.
%define min_rhel 7
%define min_fedora 30

%if (0%{?fedora} && 0%{?fedora} >= %{min_fedora}) || (0%{?rhel} && 0%{?rhel} >= %{min_rhel})
    %define supported_platform 1
%else
    %define supported_platform 0
%endif

# Default to skipping autoreconf.  Distros can change just this one line
# (or provide a command-line override) if they backport any patches that
# touch configure.ac or Makefile.am.
# Always run autoreconf
%{!?enable_autotools:%global enable_autotools 1}

# The hypervisor drivers that run in libvirtd
%define with_qemu          0%{!?_without_qemu:1}
%define with_lxc           0%{!?_without_lxc:1}
%define with_libxl         0%{!?_without_libxl:1}
%define with_vbox          0%{!?_without_vbox:1}

%define with_qemu_tcg      %{with_qemu}

%define qemu_kvm_arches %{ix86} x86_64

%if 0%{?fedora}
    %define qemu_kvm_arches %{ix86} x86_64 %{power64} s390x %{arm} aarch64
%endif

%if 0%{?rhel}
    %define with_qemu_tcg 0
    %define qemu_kvm_arches x86_64 %{power64} aarch64 s390x
%endif

# On RHEL 7 and older macro _vpath_builddir is not defined.
%if 0%{?rhel} <= 7
    %define _vpath_builddir %{_target_platform}
%endif

%ifarch %{qemu_kvm_arches}
    %define with_qemu_kvm      %{with_qemu}
%else
    %define with_qemu_kvm      0
%endif

%if ! %{with_qemu_tcg} && ! %{with_qemu_kvm}
    %define with_qemu 0
%endif

# Then the hypervisor drivers that run outside libvirtd, in libvirt.so
%define with_openvz        0%{!?_without_openvz:1}
%define with_vmware        0%{!?_without_vmware:1}
%define with_esx           0%{!?_without_esx:1}
%define with_hyperv        0%{!?_without_hyperv:1}

# Then the secondary host drivers, which run inside libvirtd
%define with_storage_rbd      0%{!?_without_storage_rbd:1}
%if 0%{?fedora}
    %define with_storage_sheepdog 0%{!?_without_storage_sheepdog:1}
%else
    %define with_storage_sheepdog 0
%endif

%define with_storage_gluster 0%{!?_without_storage_gluster:1}
%ifnarch %{qemu_kvm_arches}
    # gluster is only built where qemu driver is enabled on RHEL 8
    %if 0%{?rhel} >= 8
        %define with_storage_gluster 0
    %endif
%endif

%define with_numactl          0%{!?_without_numactl:1}

# F25+ has zfs-fuse
%if 0%{?fedora}
    %define with_storage_zfs      0%{!?_without_storage_zfs:1}
%else
    %define with_storage_zfs      0
%endif

# We need a recent enough libiscsi (>= 1.18.0)
%if 0%{?fedora} || 0%{?rhel} > 7
    %define with_storage_iscsi_direct 0%{!?_without_storage_iscsi_direct:1}
%else
    %define with_storage_iscsi_direct 0
%endif

# A few optional bits off by default, we enable later
%define with_fuse          0%{!?_without_fuse:0}
%define with_sanlock       0%{!?_without_sanlock:0}
%define with_numad         0%{!?_without_numad:0}
%define with_firewalld     0%{!?_without_firewalld:0}
%define with_firewalld_zone 0%{!?_without_firewalld_zone:0}
%define with_libssh2       0%{!?_without_libssh2:0}
%define with_wireshark     0%{!?_without_wireshark:0}
%define with_libssh        0%{!?_without_libssh:0}
%define with_bash_completion  0%{!?_without_bash_completion:0}

# Finally set the OS / architecture specific special cases

# Xen is available only on i386 x86_64 ia64
%ifnarch %{ix86} x86_64 ia64
    %define with_libxl 0
%endif

# vbox is available only on i386 x86_64
%ifnarch %{ix86} x86_64
    %define with_vbox 0
%endif

# Numactl is not available on many non-x86 archs
%ifarch s390 s390x %{arm} riscv64
    %define with_numactl 0
%endif

# zfs-fuse is not available on some architectures
%ifarch s390 s390x aarch64 riscv64
    %define with_storage_zfs 0
%endif

# Ceph dropping support for 32-bit hosts
%if 0%{?fedora} >= 30
    %ifarch %{arm} %{ix86}
        %define with_storage_rbd 0
    %endif
%endif

# RHEL doesn't ship OpenVZ, VBox, PowerHypervisor,
# VMware, libxenlight (Xen 4.1 and newer),
# or HyperV.
%if 0%{?rhel}
    %define with_openvz 0
    %define with_vbox 0
    %define with_vmware 0
    %define with_libxl 0
    %define with_hyperv 0
    %define with_vz 0

    %if 0%{?rhel} > 7
        %define with_lxc 0
    %endif
%endif

%define with_firewalld 1

%if 0%{?fedora} >= 31 || 0%{?rhel} > 7
    %define with_firewalld_zone 0%{!?_without_firewalld_zone:1}
%endif


# fuse is used to provide virtualized /proc for LXC
%if %{with_lxc}
    %define with_fuse      0%{!?_without_fuse:1}
%endif

# Enable sanlock library for lock management with QEMU
# Sanlock is available only on arches where kvm is available for RHEL
%if 0%{?fedora}
    %define with_sanlock 0%{!?_without_sanlock:1}
%endif
%if 0%{?rhel}
    %ifarch %{qemu_kvm_arches}
        %define with_sanlock 0%{!?_without_sanlock:1}
    %endif
%endif

# Enable libssh2 transport for new enough distros
%if 0%{?fedora}
    %define with_libssh2 0%{!?_without_libssh2:1}
%endif

# Enable wireshark plugins for all distros shipping libvirt 1.2.2 or newer
%if 0%{?fedora}
    %define with_wireshark 0%{!?_without_wireshark:1}
    %define wireshark_plugindir %(pkg-config --variable plugindir wireshark)/epan
%endif

# Enable libssh transport for new enough distros
%if 0%{?fedora} || 0%{?rhel} > 7
    %define with_libssh 0%{!?_without_libssh:1}
%endif

%define with_bash_completion  0%{!?_without_bash_completion:1}

%if %{with_qemu} || %{with_lxc}
# numad is used to manage the CPU and memory placement dynamically,
# it's not available on many non-x86 architectures.
    %ifnarch s390 s390x %{arm} riscv64
        %define with_numad    0%{!?_without_numad:1}
    %endif
%endif

# Force QEMU to run as non-root
%define qemu_user  qemu
%define qemu_group  qemu


# RHEL releases provide stable tool chains and so it is safe to turn
# compiler warning into errors without being worried about frequent
# changes in reported warnings
%if 0%{?rhel}
    %define enable_werror --enable-werror
%else
    %define enable_werror --disable-werror
%endif

%if 0%{?rhel} == 7
    %define tls_priority "NORMAL"
%else
    %define tls_priority "@LIBVIRT,SYSTEM"
%endif


Summary: Library providing a simple virtualization API
Name: libvirt
Version: 6.0.0
Release: 29%{?dist}%{?extra_release}
License: LGPLv2+
URL: https://libvirt.org/

%if %(echo %{version} | grep -q "\.0$"; echo $?) == 1
    %define mainturl stable_updates/
%endif
Source: https://libvirt.org/sources/%{?mainturl}libvirt-%{version}.tar.xz
Source1: symlinks

Patch1: libvirt-RHEL-Hack-around-changed-Broadwell-Haswell-CPUs.patch
Patch2: libvirt-RHEL-Add-rhel-machine-types-to-qemuDomainMachineNeedsFDC.patch
Patch3: libvirt-RHEL-Fix-virConnectGetMaxVcpus-output.patch
Patch4: libvirt-RHEL-qemu-Add-ability-to-set-sgio-values-for-hostdev.patch
Patch5: libvirt-RHEL-qemu-Add-check-for-unpriv-sgio-for-SCSI-generic-host-device.patch
Patch6: libvirt-RHEL-qemu-Alter-val-usage-in-qemuSetUnprivSGIO.patch
Patch7: libvirt-RHEL-qemu-Alter-qemuSetUnprivSGIO-hostdev-shareable-logic.patch
Patch8: libvirt-RHEL-qemu-Fix-logic-error-in-qemuSetUnprivSGIO.patch
Patch9: libvirt-RHEL-qemu-Fix-crash-trying-to-use-iSCSI-hostdev.patch
Patch10: libvirt-qemuDomainSaveImageStartVM-Use-VIR_AUTOCLOSE-for-intermediatefd.patch
Patch11: libvirt-qemuDomainSaveImageStartVM-Use-g_autoptr-for-virCommand.patch
Patch12: libvirt-qemu-Use-g_autoptr-for-qemuDomainSaveCookie.patch
Patch13: libvirt-qemu-Stop-domain-on-failed-restore.patch
Patch14: libvirt-qemu-Don-t-emit-SUSPENDED_POSTCOPY-event-on-destination.patch
Patch15: libvirt-util-storagefile-Properly-set-transport-type-when-parsing-NBD-strings.patch
Patch16: libvirt-tests-virstorage-Add-tests-for-NBD-URI-style-syntax-over-UNIX.patch
Patch17: libvirt-qemu-end-the-agent-job-in-qemuDomainSetTimeAgent.patch
Patch18: libvirt-cpu.c-Check-properly-for-virCapabilitiesGetNodeInfo-retval.patch
Patch19: libvirt-qemu_conf-Avoid-dereferencing-NULL-in-virQEMUDriverGetHost-NUMACaps-CPU.patch
Patch20: libvirt-qemu_capabilities-Rework-domain-caps-cache.patch
Patch21: libvirt-conf-add-support-for-specifying-CPU-dies-parameter.patch
Patch22: libvirt-conf-remove-unused-virCapabilitiesSetHostCPU-method.patch
Patch23: libvirt-qemu-add-support-for-specifying-CPU-dies-topology-parameter.patch
Patch24: libvirt-hostcpu-add-support-for-reporting-die_id-in-NUMA-topology.patch
Patch25: libvirt-tests-add-host-CPU-data-files-for-validating-die_id.patch
Patch26: libvirt-qemu-add-capabilities-flag-for-failover-feature.patch
Patch27: libvirt-conf-parse-format-teaming-subelement-of-interface.patch
Patch28: libvirt-qemu-support-interface-teaming-functionality.patch
Patch29: libvirt-qemu-allow-migration-with-assigned-PCI-hostdev-if-teaming-is-set.patch
Patch30: libvirt-qemu-add-wait-unplug-to-qemu-migration-status-enum.patch
Patch31: libvirt-docs-document-interface-subelement-teaming.patch
Patch32: libvirt-qemu-blockcopy-Actually-unplug-unused-images-when-mirror-job-fails-to-start.patch
Patch33: libvirt-qemu-domain-Extract-code-to-determine-topmost-nodename-to-qemuDomainDiskGetTopNodename.patch
Patch34: libvirt-qemu-Fix-value-of-device-argument-for-blockdev-mirror.patch
Patch35: libvirt-qemu-Fix-value-of-device-argument-for-block-commit.patch
Patch36: libvirt-conf-backup-Allow-configuration-of-names-exported-via-NBD.patch
Patch37: libvirt-qemu-backup-Implement-support-for-backup-disk-export-name-configuration.patch
Patch38: libvirt-qemu-backup-Implement-support-for-backup-disk-bitmap-name-configuration.patch
Patch39: libvirt-util-hash-Improve-debugability-of-Duplicate-key-error-message.patch
Patch40: libvirt-tests-hash-Test-case-for-adding-duplicate-hash-entry.patch
Patch41: libvirt-qemu-block-Don-t-skip-creation-of-luks-formatted-images.patch
Patch42: libvirt-qemu-monitor-Improve-error-message-when-QEMU-reply-is-too-large.patch
Patch43: libvirt-qemu-snapshot-Always-rewrite-backingStore-data-when-reusing-existing-images.patch
Patch44: libvirt-qemu-snapshot-Prevent-too-nested-domain-XML-when-doing-inactive-snapshot.patch
Patch45: libvirt-qemu-checkpoint-Store-whether-deleted-checkpoint-is-current-in-a-variable.patch
Patch46: libvirt-qemu-checkpoint-split-out-checkpoint-deletion-bitmaps.patch
Patch47: libvirt-qemu-checkpoint-rename-disk-chkdisk-in-qemuCheckpointDiscardBitmaps.patch
Patch48: libvirt-qemu-checkpoint-rename-disk-chkdisk-in-qemuCheckpointAddActions.patch
Patch49: libvirt-qemu-checkpoint-Use-disk-definition-directly-when-creating-checkpoint.patch
Patch50: libvirt-qemu-checkpoint-tolerate-missing-disks-on-checkpoint-deletion.patch
Patch51: libvirt-qemu-domain-Remove-unused-qemuDomainDiskNodeFormatLookup.patch
Patch52: libvirt-qemu-checkpoint-Introduce-helper-to-find-checkpoint-disk-definition-in-parents.patch
Patch53: libvirt-qemu-checkpoint-Extract-calculation-of-bitmap-merging-for-checkpoint-deletion.patch
Patch54: libvirt-qemu-snapshot-go-through-cleanup-on-error.patch
Patch55: libvirt-util-hash-Use-g_new0-for-allocating-hash-internals.patch
Patch56: libvirt-conf-domain-Remove-checking-of-return-value-of-virHashCreateFull.patch
Patch57: libvirt-Remove-checking-of-return-value-of-virHashNew.patch
Patch58: libvirt-qemuMigrationCookieAddNBD-Exit-early-if-there-are-no-disks.patch
Patch59: libvirt-qemuMigrationCookieNBD-Extract-embedded-struct.patch
Patch60: libvirt-qemuMigrationCookieAddNBD-Use-glib-memory-allocators.patch
Patch61: libvirt-qemuMigrationCookieAddNBD-Move-monitor-call-out-of-the-loop.patch
Patch62: libvirt-qemuMigrationCookieAddNBD-Use-virHashNew-and-automatic-freeing-of-virHashTablePtr.patch
Patch63: libvirt-qemuMigrationCookieAddNBD-Remove-ret-variable-and-cleanup-label.patch
Patch64: libvirt-qemuMigrationCookieAddNBD-Fix-filling-of-capacity-when-blockdev-is-used.patch
Patch65: libvirt-tests-qemublock-Add-test-for-checkpoint-deletion-bitmap-merge.patch
Patch66: libvirt-tests-qemublock-Add-few-more-test-cases-for-checkpoint-deletion.patch
Patch67: libvirt-tests-qemublock-Add-synthetic-snapshot-checkpoint-test-data.patch
Patch68: libvirt-qemu-checkpoint-Introduce-support-for-deleting-checkpoints-accross-snapshots.patch
Patch69: libvirt-tests-qemublock-Add-checkpoint-deletion-test-for-deep-backing-chain.patch
Patch70: libvirt-tests-qemublock-Add-checkpoint-deletion-tests-for-some-special-cases.patch
Patch71: libvirt-qemu-checkpoint-Track-and-relabel-images-for-bitmap-merging.patch
Patch72: libvirt-qemu-block-Extract-calls-of-qemuBlockGetNamedNodeData-into-a-helper-function.patch
Patch73: libvirt-util-json-Introduce-virJSONValueArrayConcat.patch
Patch74: libvirt-virJSONValueNewArray-Use-g_new0-to-allocate-and-remove-NULL-checks-from-callers.patch
Patch75: libvirt-virhash-Fix-the-expectations-of-virHashKeyEqual-implementations.patch
Patch76: libvirt-virHashAddOrUpdateEntry-Simplify-allocation-of-new-entry.patch
Patch77: libvirt-qemu-blockjob-Store-jobflags-with-block-job-data.patch
Patch78: libvirt-qemu-blockjob-Store-flags-for-all-the-block-job-types.patch
Patch79: libvirt-qemu-block-Add-validator-for-bitmap-chains-accross-backing-chains.patch
Patch80: libvirt-tests-qemublocktest-Add-another-synthetic-test-case-for-broken-bitmaps.patch
Patch81: libvirt-qemu-block-Introduce-function-to-calculate-bitmap-handling-for-block-copy.patch
Patch82: libvirt-tests-qemublock-Add-tests-for-qemuBlockBitmapsHandleBlockcopy.patch
Patch83: libvirt-qemuDomainBlockPivot-Copy-bitmaps-backing-checkpoints-for-virDomainBlockCopy.patch
Patch84: libvirt-docs-domaincaps-Mention-VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA.patch
Patch85: libvirt-qemu-do-not-revert-to-NULL-bandwidth.patch
Patch86: libvirt-qemu-preserve-error-on-bandwidth-rollback.patch
Patch87: libvirt-tests-Add-capabilities-for-QEMU-5.0.0-on-aarch64.patch
Patch88: libvirt-qemu-Use-switch-statement-in-qemuBuildCpuCommandLine.patch
Patch89: libvirt-qemu-Add-the-QEMU_CAPS_CPU_KVM_NO_ADJVTIME-capability.patch
Patch90: libvirt-conf-Introduce-VIR_DOMAIN_TIMER_NAME_ARMVTIMER.patch
Patch91: libvirt-qemu-Validate-configuration-for-the-armvtimer-timer.patch
Patch92: libvirt-qemu-Format-the-armvtimer-timer-on-the-command-line.patch
Patch93: libvirt-tests-Add-test-case-for-the-armvtimer-timer.patch
Patch94: libvirt-docs-List-the-armvtimer-timer-among-all-others.patch
Patch95: libvirt-qemu_domain-Modify-access-to-a-NVMe-disk-iff-needed.patch
Patch96: libvirt-qemuBlockStorageSourceGetBackendProps-Report-errors-on-all-switch-cases.patch
Patch97: libvirt-virDomainDiskAddISCSIPoolSourceHost-Sanitize-handling-of-string-list.patch
Patch98: libvirt-virDomainDiskAddISCSIPoolSourceHost-use-g_new0-instead-of-VIR_ALLOC_N.patch
Patch99: libvirt-virDomainDiskAddISCSIPoolSourceHost-Remove-cleanup-label.patch
Patch100: libvirt-virDomainDiskAddISCSIPoolSourceHost-Remove-ternary-operator.patch
Patch101: libvirt-virDomainDiskAddISCSIPoolSourceHost-Take-virStorageSourcePtr-instead-of-virDomainDiskDefPtr.patch
Patch102: libvirt-virDomainDiskTranslateSourcePoolAuth-Take-virStorageSourcePtr-instead-of-virDomainDiskDefPtr.patch
Patch103: libvirt-virDomainDiskTranslateISCSIDirect-Take-virStorageSourcePtr-instead-of-virDomainDiskDefPtr.patch
Patch104: libvirt-virDomainDiskTranslateSourcePool-split-code-to-setup-one-storage-source.patch
Patch105: libvirt-virDomainDiskTranslateSourcePool-Translate-volume-disks-in-whole-backing-chain.patch
Patch106: libvirt-qemuMonitorJSONBlockdevAdd-Refactor-cleanup.patch
Patch107: libvirt-qemuMonitorJSONBlockdevDel-Refactor-cleanup.patch
Patch108: libvirt-qemuMonitorBlockdevAdd-Take-double-pointer-argument.patch
Patch109: libvirt-qemu-hotplug-Fix-handling-of-the-copy-on-read-layer-with-blockdev.patch
Patch110: libvirt-virStorageSourceParseBackingJSON-Pass-around-original-backing-file-string.patch
Patch111: libvirt-virStorageSourceParseBackingJSON-Move-deflattening-of-json-URIs-out-of-recursion.patch
Patch112: libvirt-virStorageSourceJSONDriverParser-annotate-format-drivers.patch
Patch113: libvirt-virStorageSourceParseBackingJSON-Allow-json-pseudo-URIs-without-file-wrapper.patch
Patch114: libvirt-virStorageSourceParseBackingJSON-Prevent-arbitrary-nesting-with-format-drivers.patch
Patch115: libvirt-tests-virstorage-Add-test-cases-for-json-pseudo-URI-without-file-wrapper.patch
Patch116: libvirt-qemu-domain-Refactor-formatting-of-node-names-into-status-XML.patch
Patch117: libvirt-docs-formatdomain-Close-source-on-one-of-disk-examples.patch
Patch118: libvirt-tests-virstorage-Add-test-data-for-json-specified-raw-image-with-offset-size.patch
Patch119: libvirt-util-virstoragefile-Add-data-structure-for-storing-storage-source-slices.patch
Patch120: libvirt-qemuBlockStorageSourceGetFormatRawProps-format-offset-and-size-for-slice.patch
Patch121: libvirt-qemuDomainValidateStorageSource-Reject-unsupported-slices.patch
Patch122: libvirt-qemu-block-forbid-creation-of-storage-sources-with-slice.patch
Patch123: libvirt-docs-Document-the-new-slices-sub-element-of-disk-s-source.patch
Patch124: libvirt-conf-Implement-support-for-slices-of-disk-source.patch
Patch125: libvirt-qemu-domain-Store-nodenames-of-slice-in-status-XML.patch
Patch126: libvirt-qemu-block-Properly-format-storage-slice-into-backing-store-strings.patch
Patch127: libvirt-tests-qemublock-Add-cases-for-creating-image-overlays-on-top-of-disks-with-slice.patch
Patch128: libvirt-qemu-Add-support-for-slices-of-type-storage.patch
Patch129: libvirt-tests-qemu-Add-test-data-for-the-new-slice-element.patch
Patch130: libvirt-virStorageSourceParseBackingJSONRaw-Parse-offset-and-size-attributes.patch
Patch131: libvirt-qemuDomainGetStatsIOThread-Don-t-leak-array-with-0-iothreads.patch
Patch132: libvirt-qemuxml2xmltest-Add-case-for-host-model-vendor_id.patch
Patch133: libvirt-cpu_conf-Format-vendor_id-for-host-model-CPUs.patch
Patch134: libvirt-qemu-rename-qemuAgentGetFSInfoInternalDisk.patch
Patch135: libvirt-qemu-store-complete-agent-filesystem-information.patch
Patch136: libvirt-qemu-Don-t-store-disk-alias-in-qemuAgentDiskInfo.patch
Patch137: libvirt-qemu-don-t-access-vmdef-within-qemu_agent.c.patch
Patch138: libvirt-qemu-remove-qemuDomainObjBegin-EndJobWithAgent.patch
Patch139: libvirt-docs-fix-a-typo.patch
Patch140: libvirt-virDomainNetDefClear-Free-persistent-name.patch
Patch141: libvirt-virSecurityManagerMetadataLock-Store-locked-paths.patch
Patch142: libvirt-security-Don-t-remember-seclabel-for-paths-we-haven-t-locked-successfully.patch
Patch143: libvirt-security-Don-t-fail-if-locking-a-file-on-NFS-mount-fails.patch
Patch144: libvirt-util-storagefile-Drop-image-format-probing-by-file-suffix.patch
Patch145: libvirt-virStorageFileGetMetadataRecurse-Remove-impossible-error-report.patch
Patch146: libvirt-virStorageFileGetMetadataRecurse-Shuffle-around-assignment-of-backing-chain-depth.patch
Patch147: libvirt-virStorageFileGetMetadataRecurse-Expect-NULL-src-path.patch
Patch148: libvirt-virStorageFileGetMetadataRecurse-Use-virHashHasEntry-instead-of-fake-pointers.patch
Patch149: libvirt-virStorageFileGetMetadataRecurse-Extract-storage-access.patch
Patch150: libvirt-virStorageFileGetMetadataRecurse-Remove-cleanup-label.patch
Patch151: libvirt-tests-virstorage-Fix-backing-file-format-of-created-image.patch
Patch152: libvirt-virStorageSourceUpdateCapacity-Drop-probe-argument.patch
Patch153: libvirt-util-storage-Store-backing-store-format-in-virStorageSource.patch
Patch154: libvirt-virStorageSourceNewFromBacking-Also-transfer-the-format.patch
Patch155: libvirt-virStorageBackendGlusterRefreshVol-Refactor-handling-of-backing-store.patch
Patch156: libvirt-virStorageFileGetMetadataFromBuf-Remove-backingFormat-argument.patch
Patch157: libvirt-virStorageFileGetMetadataFromFD-Remove-unused-backingFormat-argument.patch
Patch158: libvirt-qemu-domain-Convert-detected-iso-image-format-into-raw.patch
Patch159: libvirt-virStorageFileGetMetadataRecurse-Allow-format-probing-under-special-circumstances.patch
Patch160: libvirt-kbase-backing_chains-Clarify-some-aspects-of-image-probing.patch
Patch161: libvirt-kbase-backing_chains-Add-steps-how-to-securely-probe-image-format.patch
Patch162: libvirt-conf-use-virXMLFormatElement-in-virDomainFSDefFormat.patch
Patch163: libvirt-qemu-use-def-instead-of-vm-def-in-qemuExtDevicesStart.patch
Patch164: libvirt-qemu-eliminate-ret-in-qemuExtDevicesStart.patch
Patch165: libvirt-docs-render-class-literal-with-monospace-font.patch
Patch166: libvirt-docs-reduce-excessive-spacing-in-ToC-for-RST-files.patch
Patch167: libvirt-virDomainFSDefFree-Unref-private-data.patch
Patch168: libvirt-schema-wrap-fsDriver-in-a-choice-group.patch
Patch169: libvirt-qemuExtDevicesStart-pass-logManager.patch
Patch170: libvirt-qemu-pass-virDomainObjPtr-to-qemuExtDevicesSetupCgroup.patch
Patch171: libvirt-qemuxml2xmltest-set-driver-as-privileged.patch
Patch172: libvirt-qemu-add-QEMU_CAPS_DEVICE_VHOST_USER_FS.patch
Patch173: libvirt-docs-add-virtiofs-kbase.patch
Patch174: libvirt-conf-qemu-add-virtiofs-fsdriver-type.patch
Patch175: libvirt-conf-add-virtiofs-related-elements-and-attributes.patch
Patch176: libvirt-qemu-add-virtiofsd_debug-to-qemu.conf.patch
Patch177: libvirt-qemu-validate-virtiofs-filesystems.patch
Patch178: libvirt-qemu-forbid-migration-with-vhost-user-fs-device.patch
Patch179: libvirt-qemu-add-code-for-handling-virtiofsd.patch
Patch180: libvirt-qemu-put-virtiofsd-in-the-emulator-cgroup.patch
Patch181: libvirt-qemu-use-the-vhost-user-schemas-to-find-binary.patch
Patch182: libvirt-qemu-build-vhost-user-fs-device-command-line.patch
Patch183: libvirt-RHEL-virscsi-Check-device-type-before-getting-it-s-dev-node-name.patch
Patch184: libvirt-RHEL-virscsi-Support-TAPEs-in-virSCSIDeviceGetDevName.patch
Patch185: libvirt-RHEL-virscsi-Introduce-and-use-virSCSIDeviceGetUnprivSGIOSysfsPath.patch
Patch186: libvirt-RHEL-virutil-Accept-non-block-devices-in-virGetDeviceID.patch
Patch187: libvirt-RHEL-qemuSetUnprivSGIO-Actually-use-calculated-sysfs_path-to-set-unpriv_sgio.patch
Patch188: libvirt-RHEL-qemuCheckUnprivSGIO-use-sysfs_path-to-get-unpriv_sgio.patch
Patch189: libvirt-security-Introduce-VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP-flag.patch
Patch190: libvirt-qemu-Tell-secdrivers-which-images-are-top-parent.patch
Patch191: libvirt-virDomainDiskTranslateSourcePool-Check-for-disk-type-correctly.patch
Patch192: libvirt-virbuftest-remove-extra-G_GNUC_UNUSED-markers.patch
Patch193: libvirt-virbuftest-use-g_autofree.patch
Patch194: libvirt-virbuftest-remove-unnecessary-labels.patch
Patch195: libvirt-virbuftest-declare-testBufAddStrData-earlier.patch
Patch196: libvirt-virbuftest-use-field-names-when-initalizing-test-info.patch
Patch197: libvirt-util-add-virBufferTrimChars.patch
Patch198: libvirt-conf-do-not-generate-machine-names-ending-with-a-dash.patch
Patch199: libvirt-conf-Don-t-generate-machine-names-with-a-dot.patch
Patch200: libvirt-qemuAgentFSInfoFormatParams-Remove-pointless-returned-value.patch
Patch201: libvirt-qemuDomainGetGuestInfo-Don-t-try-to-free-a-negative-number-of-entries.patch
Patch202: libvirt-qemuDomainBlockPivot-Move-check-prior-to-executing-the-pivot-steps.patch
Patch203: libvirt-qemuDomainBlockCopyCommon-Record-updated-flags-to-block-job.patch
Patch204: libvirt-qemu-capabilities-Introduce-QEMU_CAPS_BLOCKDEV_SNAPSHOT_ALLOW_WRITE_ONLY.patch
Patch205: libvirt-qemu-blockcopy-Allow-late-opening-of-the-backing-chain-of-a-shallow-copy.patch
Patch206: libvirt-qemuBlockStorageSourceDetachPrepare-Get-rid-of-cleanup-section.patch
Patch207: libvirt-qemu-Don-t-take-double-pointer-in-qemuDomainSecretInfoFree.patch
Patch208: libvirt-qemuMigrationParamsResetTLS-Adapt-to-modern-memory-management.patch
Patch209: libvirt-qemuMigrationParamsResetTLS-Fix-comment.patch
Patch210: libvirt-qemuDomainSecretInfo-Register-autoptr-cleanup-function.patch
Patch211: libvirt-qemuDomainSecretAESSetup-Automatically-free-non-secret-locals.patch
Patch212: libvirt-qemuDomainSecretAESSetup-Allocate-and-return-secinfo-here.patch
Patch213: libvirt-qemuDomainSecretAESSetup-Split-out-lookup-of-secret-data.patch
Patch214: libvirt-Remove-qemuDomainSecretInfoNew.patch
Patch215: libvirt-qemu-Introduce-another-helper-for-creating-alias-for-a-secret-object.patch
Patch216: libvirt-qemuDomainSecretStorageSourcePrepare-Fix-naming-of-alias-variables.patch
Patch217: libvirt-qemuDomainDeviceDiskDefPostParseRestoreSecAlias-Hardcode-restored-aliases.patch
Patch218: libvirt-qemu-Split-out-initialization-of-secrets-for-iscsi-hostdevs.patch
Patch219: libvirt-qemuDomainSecretAESSetupFromSecret-Use-qemuAliasForSecret.patch
Patch220: libvirt-qemuDomainSecretStorageSourcePrepare-Change-aliases-for-disk-secrets.patch
Patch221: libvirt-qemuDomainGetSecretAESAlias-Replace-outstanding-uses-with-qemuAliasForSecret.patch
Patch222: libvirt-conf-Add-support-for-modifying-ssl-validation-for-https-ftps-disks.patch
Patch223: libvirt-conf-Add-support-for-cookies-for-HTTP-based-disks.patch
Patch224: libvirt-conf-Add-support-for-setting-timeout-and-readahead-size-for-network-disks.patch
Patch225: libvirt-qemuDomainValidateStorageSource-Validate-new-network-storage-parameters.patch
Patch226: libvirt-qemuxml2argvtest-Add-test-case-for-disks-with-http-s-source.patch
Patch227: libvirt-qemu-block-Implement-ssl-verification-configuration.patch
Patch228: libvirt-qemu-domain-Store-data-for-secret-object-representing-http-cookies.patch
Patch229: libvirt-qemuDomainSecretStorageSourcePrepare-Setup-secret-for-http-cookies.patch
Patch230: libvirt-qemu-Handle-hotplug-and-commandline-for-secret-objects-for-http-cookies.patch
Patch231: libvirt-qemu-block-Add-support-for-HTTP-cookies.patch
Patch232: libvirt-qemu-block-Implement-readahead-and-timeout-properties-for-curl-driver.patch
Patch233: libvirt-virstoragefile-Add-JSON-parser-for-sslverify-readahead-cookies-and-timeout.patch
Patch234: libvirt-virStorageSourceParseBackingJSONUri-Handle-undocumented-value-off-for-sslverify.patch
Patch235: libvirt-qemublocktest-Load-QMP-schema-earlier.patch
Patch236: libvirt-qemublocktest-Extract-schema-root-for-blockdev-add-validation.patch
Patch237: libvirt-qemublocktest-XMLjsonXML-Test-formatting-parsing-of-modern-JSON.patch
Patch238: libvirt-qemublocktest-Add-JSON-JSON-test-cases-for-block-device-backends.patch
Patch239: libvirt-qemu-Pass-through-arguments-of-ssh-block-driver-used-by-libguestfs.patch
Patch240: libvirt-qemu-capabilities-Add-QEMU_CAPS_BLOCKDEV_REOPEN.patch
Patch241: libvirt-qemu-monitor-Add-handler-for-blockdev-reopen.patch
Patch242: libvirt-qemu-block-implement-helpers-for-blockdev-reopen.patch
Patch243: libvirt-qemuCheckpointDiscardBitmaps-Reopen-images-for-bitmap-modifications.patch
Patch244: libvirt-qemuCheckpointDiscardBitmaps-Use-correct-field-for-checkpoint-bitmap-name.patch
Patch245: libvirt-qemuDomainBlockCommit-Move-checks-depending-on-capabilities-after-liveness-check.patch
Patch246: libvirt-qemu-domain-Extract-formatting-of-commit-blockjob-data-into-a-function.patch
Patch247: libvirt-qemu-domain-Extract-parsing-of-commit-blockjob-data-into-a-function.patch
Patch248: libvirt-qemu-blockjob-Store-list-of-bitmaps-disabled-prior-to-commit.patch
Patch249: libvirt-qemublocktest-Fix-and-optimize-fake-image-chain.patch
Patch250: libvirt-qemu-block-Implement-helpers-for-dealing-with-bitmaps-during-block-commit.patch
Patch251: libvirt-qemublocktest-Add-tests-for-handling-of-bitmaps-during-block-commit.patch
Patch252: libvirt-qemublocktest-Add-more-tests-for-block-commit-bitmap-handling-with-snapshots.patch
Patch253: libvirt-qemublocktest-Add-tests-of-broken-bitmap-chain-handling-during-block-commit.patch
Patch254: libvirt-qemuBlockJobDiskNewCommit-Propagate-disabledBitmapsBase.patch
Patch255: libvirt-qemuDomainBlockCommit-Handle-bitmaps-on-start-of-commit.patch
Patch256: libvirt-qemuDomainBlockPivot-Handle-merging-of-bitmaps-when-pivoting-an-active-block-commit.patch
Patch257: libvirt-qemu-blockjob-Handle-bitmaps-after-finish-of-normal-block-commit.patch
Patch258: libvirt-qemu-blockjob-Re-enable-bitmaps-after-failed-block-commit.patch
Patch259: libvirt-qemuDomainGetGuestInfo-don-t-assign-NULL-hostname.patch
Patch260: libvirt-rhel-Enable-usage-of-x-blockdev-reopen.patch
Patch261: libvirt-qemuBlockBitmapsHandleCommitStart-Fix-allocation-of-string-list.patch
Patch262: libvirt-qemuBlockBitmapsHandleCommitFinish-Use-proper-variable-to-iterate.patch
Patch263: libvirt-qemublocktest-Add-tests-for-re-enabling-of-bitmaps-after-commit.patch
Patch264: libvirt-qemu-Create-multipath-targets-for-PRs.patch
Patch265: libvirt-qemu-Don-t-crash-when-getting-targets-for-a-multipath.patch
Patch266: libvirt-virSecretLookupDefCopy-Remove-return-value.patch
Patch267: libvirt-virStorageEncryptionSecretCopy-Properly-copy-internals.patch
Patch268: libvirt-vmx-shortcut-earlier-few-ignore-cases-in-virVMXParseDisk.patch
Patch269: libvirt-vmx-make-fileName-optional-for-CD-ROMs.patch
Patch270: libvirt-qemublocktest-Backport-cleanups-for-testQemuDiskXMLToProps-from-dd94f36ffbe.patch
Patch271: libvirt-conf-rename-namespace-property-of-struct-_virStorageSourceNVMeDef.patch
Patch272: libvirt-qemublocktest-xml-json-Add-test-for-NVMe.patch
Patch273: libvirt-virDomainDiskSourceNVMeFormat-Format-only-valid-managed-values.patch
Patch274: libvirt-qemublocktest-xml-json-Refactor-cleanup-in-test-case-functions.patch
Patch275: libvirt-testQemuDiskXMLToPropsValidateFileSrcOnly-Move-together-with-rest-of-xml-json-code.patch
Patch276: libvirt-qemuBlockGetBackingStoreString-Add-pretty-argument.patch
Patch277: libvirt-testQemuDiskXMLToProps-Store-all-per-image-data-in-one-structure.patch
Patch278: libvirt-qemublocktest-Test-backing-store-strings.patch
Patch279: libvirt-qemuBlockGetBackingStoreString-Remove-ret-variable.patch
Patch280: libvirt-storage-Implement-backing-store-support-for-fat-prefix.patch
Patch281: libvirt-qemuBlockGetBackingStoreString-Add-extra-wrapping-object-to-JSON-strings.patch
Patch282: libvirt-qemu-block-Extract-formatting-of-cookie-string.patch
Patch283: libvirt-qemuBlockGetBackingStoreString-Properly-handle-http-s-with-cookies-and-others.patch
Patch284: libvirt-storage-Parse-nvme-disk-source-properties-from-json-pseudo-uri.patch
Patch285: libvirt-qemu-virtiofs-shorten-pid-filename.patch
Patch286: libvirt-qemu-virtiofs-shorten-socket-filename.patch
Patch287: libvirt-api-disallow-virDomainAgentSetResponseTimeout-on-read-only-connections.patch
Patch288: libvirt-qemuBackupBegin-Fix-monitor-access-when-rolling-back-due-to-failure.patch
Patch289: libvirt-qemuxml2xmltest-Wire-up-disk-network-http-case.patch
Patch290: libvirt-virStorageSourceNetCookieValidate-Accept-quoted-cookie-value.patch
Patch291: libvirt-qemu-block-Support-VIR_DOMAIN_BLOCK_COMMIT-PULL-REBASE_RELATIVE-with-blockdev.patch
Patch292: libvirt-qemuDomainSnapshotDiskPrepareOne-Don-t-load-the-relative-path-with-blockdev.patch
Patch293: libvirt-docs-formatdomain-Mention-missing-protocols.patch
Patch294: libvirt-schemas-rng-Use-interleave-in-the-disk-source-element.patch
Patch295: libvirt-conf-Add-support-for-http-s-query-strings.patch
Patch296: libvirt-qemuBlockStorageSourceGetURI-Pass-through-query-component.patch
Patch297: libvirt-virStorageSourceParseBackingURI-Preserve-query-string-of-URI-for-http-s.patch
Patch298: libvirt-qemuDomainSnapshotDiskPrepareOne-Fix-logic-of-relative-backing-store-update.patch
Patch299: libvirt-qemuCheckpointCreateXML-Check-VM-liveness-first.patch
Patch300: libvirt-qemu-checkpoint-Allow-checkpoint-redefine-for-offline-VMs.patch
Patch301: libvirt-virDomainCheckpointRedefinePrep-Set-current-checkpoint-if-there-isn-t-any.patch
Patch302: libvirt-qemu-avoid-launching-non-x86-guests-with-APIC-EOI-setting.patch
Patch303: libvirt-tests-qemu-add-disk-error-policy-tests-for-s390x.patch
Patch304: libvirt-qemu-add-QEMU_CAPS_STORAGE_WERROR.patch
Patch305: libvirt-qemu-use-QEMU_CAPS_STORAGE_WERROR-for-disk-error-attributes.patch
Patch306: libvirt-qemuMonitorTestProcessCommandDefaultValidate-Output-validator-output-to-stderr.patch
Patch307: libvirt-qemumonitorjsontest-AddNetdev-Use-real-variant.patch
Patch308: libvirt-qemu-new-capabilities-flag-pcie-root-port.hotplug.patch
Patch309: libvirt-conf-new-attribute-hotplug-for-pci-controllers.patch
Patch310: libvirt-qemu-hook-up-pcie-root-port-hotplug-off-option.patch
Patch311: libvirt-docs-mention-hotplug-off-in-news.xml.patch
Patch312: libvirt-conf-add-new-PCI_CONNECT-flag-AUTOASSIGN.patch
Patch313: libvirt-conf-qemu-s-VIR_PCI_CONNECT_HOTPLUGGABLE-VIR_PCI_CONNECT_AUTOASSIGN-g.patch
Patch314: libvirt-conf-simplify-logic-when-checking-for-AUTOASSIGN-PCI-addresses.patch
Patch315: libvirt-qemu-conf-set-HOTPLUGGABLE-connect-flag-during-PCI-address-set-init.patch
Patch316: libvirt-conf-check-HOTPLUGGABLE-connect-flag-when-validating-a-PCI-address.patch
Patch317: libvirt-conf-during-PCI-hotplug-require-that-the-controller-support-hotplug.patch
Patch318: libvirt-qemu-fix-detection-of-vCPU-pids-when-multiple-dies-are-present.patch
Patch319: libvirt-storage_file-create-Create-new-images-with-write-permission-bit.patch
Patch320: libvirt-qemuBlockStorageSourceCreateFormat-Force-write-access-when-formatting-images.patch
Patch321: libvirt-qemu-snapshot-Allow-snapshots-of-read-only-disks-when-we-can-create-them.patch
Patch322: libvirt-qemu-blockcopy-Allow-copy-of-read-only-disks-with-blockdev.patch
Patch323: libvirt-virDevMapperGetTargetsImpl-quit-early-if-device-is-not-a-devmapper-target.patch
Patch324: libvirt-qemu-only-stop-external-devices-after-the-domain.patch
Patch325: libvirt-qemu-fixing-auto-detecting-binary-in-domain-capabilities.patch
Patch326: libvirt-qemu-prevent-attempts-to-detach-a-device-on-a-controller-with-hotplug-off.patch
Patch327: libvirt-cpu-Change-control-flow-in-virCPUUpdateLive.patch
Patch328: libvirt-cpu_x86-Prepare-virCPUx86UpdateLive-for-easier-extension.patch
Patch329: libvirt-cpu-Honor-check-full-for-host-passthrough-CPUs.patch
Patch330: libvirt-cputest-Add-data-for-Intel-R-Core-TM-i7-8550U-CPU-without-TSX.patch
Patch331: libvirt-cpu_map-Add-more-noTSX-x86-CPU-models.patch
Patch332: libvirt-cpu_map-Add-decode-element-to-x86-CPU-model-definitions.patch
Patch333: libvirt-cpu_x86-Honor-CPU-models-decode-element.patch
Patch334: libvirt-cpu_map-Don-t-use-new-noTSX-models-for-host-model-CPUs.patch
Patch335: libvirt-cpu_x86-Drop-noTSX-hint-for-incompatible-CPUs.patch
Patch336: libvirt-cpu_x86-Use-glib-allocation-for-virCPU-x86-Data.patch
Patch337: libvirt-cpu_x86-Use-glib-allocation-for-virCPUx86Vendor.patch
Patch338: libvirt-cpu_x86-Use-glib-allocation-for-virCPUx86Feature.patch
Patch339: libvirt-cpu_x86-Use-glib-allocation-for-virCPUx86Model.patch
Patch340: libvirt-cpu_x86-Use-glib-allocation-for-virCPUx86Map.patch
Patch341: libvirt-cpu_x86-Use-glib-allocation-in-virCPUx86GetModels.patch
Patch342: libvirt-cpu_x86-Use-g_auto-in-x86DataToCPU.patch
Patch343: libvirt-cpu_x86-Use-g_auto-in-x86VendorParse.patch
Patch344: libvirt-cpu_x86-Use-g_auto-in-x86FeatureParse.patch
Patch345: libvirt-cpu_x86-Use-g_auto-in-x86ModelFromCPU.patch
Patch346: libvirt-cpu_x86-Use-g_auto-in-x86ModelParse.patch
Patch347: libvirt-cpu_x86-Use-g_auto-in-virCPUx86LoadMap.patch
Patch348: libvirt-cpu_x86-Use-g_auto-in-virCPUx86DataParse.patch
Patch349: libvirt-cpu_x86-Use-g_auto-in-x86Compute.patch
Patch350: libvirt-cpu_x86-Use-g_auto-in-virCPUx86Compare.patch
Patch351: libvirt-cpu_x86-Use-g_auto-in-x86Decode.patch
Patch352: libvirt-cpu_x86-Use-g_auto-in-x86EncodePolicy.patch
Patch353: libvirt-cpu_x86-Use-g_auto-in-x86Encode.patch
Patch354: libvirt-cpu_x86-Use-g_auto-in-virCPUx86CheckFeature.patch
Patch355: libvirt-cpu_x86-Use-g_auto-in-virCPUx86GetHost.patch
Patch356: libvirt-cpu_x86-Use-g_auto-in-virCPUx86Baseline.patch
Patch357: libvirt-cpu_x86-Use-g_auto-in-x86UpdateHostModel.patch
Patch358: libvirt-cpu_x86-Use-g_auto-in-virCPUx86Update.patch
Patch359: libvirt-cpu_x86-Use-g_auto-in-virCPUx86UpdateLive.patch
Patch360: libvirt-cpu_x86-Use-g_auto-in-virCPUx86Translate.patch
Patch361: libvirt-cpu_x86-Use-g_auto-in-virCPUx86ExpandFeatures.patch
Patch362: libvirt-cpu_x86-Use-g_auto-in-virCPUx86CopyMigratable.patch
Patch363: libvirt-cpu_x86-Move-and-rename-x86ModelCopySignatures.patch
Patch364: libvirt-cpu_x86-Move-and-rename-x86ModelHasSignature.patch
Patch365: libvirt-cpu_x86-Move-and-rename-x86FormatSignatures.patch
Patch366: libvirt-cpu_x86-Introduce-virCPUx86SignaturesFree.patch
Patch367: libvirt-cpu_x86-Introduce-virCPUx86SignatureFromCPUID.patch
Patch368: libvirt-cpu_x86-Replace-32b-signatures-in-virCPUx86Model-with-a-struct.patch
Patch369: libvirt-cpu_x86-Don-t-check-return-value-of-x86ModelCopy.patch
Patch370: libvirt-cpu_x86-Add-support-for-stepping-part-of-CPU-signature.patch
Patch371: libvirt-cputest-Add-data-for-Intel-R-Xeon-R-Platinum-9242-CPU.patch
Patch372: libvirt-cputest-Add-data-for-Intel-R-Xeon-R-Gold-6130-CPU.patch
Patch373: libvirt-cpu_map-Distinguish-Cascadelake-Server-from-Skylake-Server.patch
Patch374: libvirt-cputest-Add-data-for-Cooperlake-CPU.patch
Patch375: libvirt-cpu_map-Add-pschange-mc-no-bit-in-IA32_ARCH_CAPABILITIES-MSR.patch
Patch376: libvirt-cpu_map-Add-Cooperlake-x86-CPU-model.patch
Patch377: libvirt-cpu_map-Distribute-x86_Cooperlake.xml.patch
Patch378: libvirt-qemu-Refuse-to-use-ps2-on-machines-that-do-not-have-this-bus.patch
Patch379: libvirt-nodedev-fix-race-in-API-usage-vs-initial-device-enumeration.patch
Patch380: libvirt-qemu-backup-Fix-handling-of-backing-store-for-backup-target-images.patch
Patch381: libvirt-qemu-backup-Split-up-code-traversing-checkpoint-list-looking-for-bitmaps.patch
Patch382: libvirt-qemu-backup-Fix-backup-of-disk-skipped-in-an-intermediate-checkpoint.patch
Patch383: libvirt-conf-backup-Store-incremental-backup-checkpoint-name-per-disk.patch
Patch384: libvirt-qemu-backup-Move-fetching-of-checkpoint-list-for-incremental-backup.patch
Patch385: libvirt-qemublocktest-Add-empty-test-case-for-bitmaps.patch
Patch386: libvirt-qemublocktest-Add-empty-case-for-incremental-backup-test.patch
Patch387: libvirt-qemublocktest-Add-empty-case-for-checkpoint-deletion.patch
Patch388: libvirt-qemublocktest-Add-empty-case-for-blockcopy-bitmap-handling-test.patch
Patch389: libvirt-qemublocktest-Add-empty-case-for-checkpoint-bitmap-handling.patch
Patch390: libvirt-qemublocktest-Disable-testcases-for-all-bitmap-handling.patch
Patch391: libvirt-qemublocktest-Delete-synthetic-bitmap-test-cases.patch
Patch392: libvirt-qemublocktest-Extract-printing-of-nodename-list.patch
Patch393: libvirt-qemu-checkpoint-Don-t-chain-bitmaps-for-checkpoints.patch
Patch394: libvirt-qemublocktest-Replace-basic-bitmap-detection-test-case-data.patch
Patch395: libvirt-qemublocktest-Replace-snapshots-bitmap-detection-test-case-data.patch
Patch396: libvirt-qemuBlockBitmapChainIsValid-Adjust-to-new-semantics-of-bitmaps.patch
Patch397: libvirt-qemublocktest-Re-add-bitmap-validation-for-basic-and-snapshots-cases.patch
Patch398: libvirt-qemublocktest-Add-new-synthetic-bitmap-detection-and-validation-test-case.patch
Patch399: libvirt-qemu-checkpoint-Don-t-merge-checkpoints-during-deletion.patch
Patch400: libvirt-qemublocktest-Rename-TEST_CHECKPOINT_DELETE_MERGE-to-TEST_CHECKPOINT_DELETE.patch
Patch401: libvirt-qemublocktest-Re-introduce-testing-of-checkpoint-deletion.patch
Patch402: libvirt-qemu-block-Add-universal-helper-for-merging-dirty-bitmaps-for-all-scenarios.patch
Patch403: libvirt-qemu-backup-Rewrite-backup-bitmap-handling-to-the-new-bitmap-semantics.patch
Patch404: libvirt-qemublocktest-Add-basic-tests-for-backup-bitmap-handling.patch
Patch405: libvirt-qemublocktest-Add-snapshots-tests-for-backup-bitmap-handling.patch
Patch406: libvirt-qemu-Rewrite-bitmap-handling-for-block-commit.patch
Patch407: libvirt-qemublocktest-Add-basic-tests-for-commit-bitmap-handling.patch
Patch408: libvirt-qemublocktest-Add-snapshots-tests-for-block-commit-bitmap-handling.patch
Patch409: libvirt-qemu-blockjob-Remove-disabledBitmapsBase-field-from-commit-job-private-data.patch
Patch410: libvirt-qemu-Rewrite-bitmap-handling-for-block-copy.patch
Patch411: libvirt-qemublocktest-Add-test-cases-for-handling-bitmaps-during-block-copy.patch
Patch412: libvirt-kbase-Add-document-outlining-internals-of-incremental-backup-in-qemu.patch
Patch413: libvirt-qemuBackupBegin-Don-t-leak-def-on-early-failures.patch
Patch414: libvirt-qemu-backup-Initialize-store-source-properly-and-just-once.patch
Patch415: libvirt-qemuBackupDiskStarted-Fix-improper-dereference-of-array.patch
Patch416: libvirt-qemuBackupDiskDataCleanupOne-Don-t-exit-early-when-the-job-has-started.patch
Patch417: libvirt-qemuBackupDiskDataCleanupOne-Free-incrementalBitmap.patch
Patch418: libvirt-util-Move-virIsDevMapperDevice-to-virdevmapper.c.patch
Patch419: libvirt-virDevMapperGetTargetsImpl-Check-for-dm-major-properly.patch
Patch420: libvirt-conf-Don-t-format-http-cookies-unless-VIR_DOMAIN_DEF_FORMAT_SECURE-is-used.patch
Patch421: libvirt-util-Introduce-a-parser-for-kernel-cmdline-arguments.patch
Patch422: libvirt-qemu-Check-if-s390-secure-guest-support-is-enabled.patch
Patch423: libvirt-qemu-Check-if-AMD-secure-guest-support-is-enabled.patch
Patch424: libvirt-tools-Secure-guest-check-on-s390-in-virt-host-validate.patch
Patch425: libvirt-tools-Secure-guest-check-for-AMD-in-virt-host-validate.patch
Patch426: libvirt-docs-Update-AMD-launch-secure-description.patch
Patch427: libvirt-docs-Describe-protected-virtualization-guest-setup.patch
Patch428: libvirt-qemu-blockjob-Don-t-base-bitmap-handling-of-active-layer-block-commit-on-QEMU_CAPS_BLOCKDEV_REOPEN.patch
Patch429: libvirt-qemu-blockjob-Actually-delete-temporary-bitmap-on-failed-active-commit.patch
Patch430: libvirt-qemu-block-Remove-active-write-bitmap-even-if-there-are-no-bitmaps-to-merge.patch
Patch431: libvirt-qemuDomainBlockPivot-Rename-actions-to-bitmapactions.patch
Patch432: libvirt-qemuDomainBlockPivot-Ignore-failures-of-creating-active-layer-bitmap.patch
Patch433: libvirt-src-assume-sys-sysmacros.h-always-exists-on-Linux.patch
Patch434: libvirt-virdevmapper.c-Join-two-WITH_DEVMAPPER-sections-together.patch
Patch435: libvirt-virDevMapperGetTargetsImpl-Use-VIR_AUTOSTRINGLIST.patch
Patch436: libvirt-virdevmapper-Don-t-use-libdevmapper-to-obtain-dependencies.patch
Patch437: libvirt-virDevMapperGetTargets-Don-t-ignore-EBADF.patch
Patch438: libvirt-virdevmapper-Don-t-cache-device-mapper-major.patch
Patch439: libvirt-virdevmapper-Handle-kernel-without-device-mapper-support.patch
Patch440: libvirt-virdevmapper-Ignore-all-errors-when-opening-dev-mapper-control.patch
Patch441: libvirt-qemu-substitute-missing-model-name-for-host-passthrough.patch
Patch442: libvirt-rpc-gendispatch-handle-empty-flags.patch
Patch443: libvirt-rpc-add-support-for-filtering-acls-by-uint-params.patch
Patch444: libvirt-rpc-require-write-acl-for-guest-agent-in-virDomainInterfaceAddresses.patch
Patch445: libvirt-qemu-agent-set-ifname-to-NULL-after-freeing.patch
Patch446: libvirt-qemu-Fix-domfsinfo-for-non-PCI-device-information-from-guest-agent.patch
Patch447: libvirt-virDomainNetFindIdx-add-support-for-CCW-addresses.patch
Patch448: libvirt-check-for-NULL-before-calling-g_regex_unref.patch
Patch449: libvirt-virhostcpu.c-fix-die_id-parsing-for-Power-hosts.patch
Patch450: libvirt-qemuFirmwareFillDomain-Fill-NVRAM-template-on-migration-too.patch
Patch451: libvirt-node_device-refactor-udevProcessCCW.patch
Patch452: libvirt-node_device-detect-CSS-devices.patch
Patch453: libvirt-virsh-nodedev-ability-to-filter-CSS-capabilities.patch
Patch454: libvirt-node_device-detect-DASD-devices.patch
Patch455: libvirt-udevProcessCSS-Check-if-def-driver-is-non-NULL.patch

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-config-network = %{version}-%{release}
Requires: libvirt-daemon-config-nwfilter = %{version}-%{release}
%if %{with_libxl}
Requires: libvirt-daemon-driver-libxl = %{version}-%{release}
%endif
%if %{with_lxc}
Requires: libvirt-daemon-driver-lxc = %{version}-%{release}
%endif
%if %{with_qemu}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
%endif
# We had UML driver, but we've removed it.
Obsoletes: libvirt-daemon-driver-uml <= 5.0.0
Obsoletes: libvirt-daemon-uml <= 5.0.0
%if %{with_vbox}
Requires: libvirt-daemon-driver-vbox = %{version}-%{release}
%endif
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}

Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-client = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

# All build-time requirements. Run-time requirements are
# listed against each sub-RPM
%if 0%{?enable_autotools}
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: gettext-devel
BuildRequires: libtool
%endif
%if 0%{?rhel} == 7
BuildRequires: python36-docutils
%else
BuildRequires: python3-docutils
%endif
BuildRequires: gcc
BuildRequires: git
%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires: perl-interpreter
%else
BuildRequires: perl
%endif
%if 0%{?rhel} > 7
BuildRequires: python3-devel
%else
BuildRequires: python3
%endif
BuildRequires: systemd-units
%if %{with_libxl}
BuildRequires: xen-devel
%endif
BuildRequires: glib2-devel >= 2.48
BuildRequires: libxml2-devel
BuildRequires: libxslt
BuildRequires: readline-devel
%if %{with_bash_completion}
BuildRequires: bash-completion >= 2.0
%endif
BuildRequires: ncurses-devel
BuildRequires: gettext
BuildRequires: libtasn1-devel
BuildRequires: gnutls-devel
BuildRequires: libattr-devel
# For pool-build probing for existing pools
BuildRequires: libblkid-devel >= 2.17
# for augparse, optionally used in testing
BuildRequires: augeas
BuildRequires: systemd-devel >= 185
BuildRequires: libpciaccess-devel >= 0.10.9
BuildRequires: yajl-devel
%if %{with_sanlock}
BuildRequires: sanlock-devel >= 2.4
%endif
BuildRequires: libpcap-devel
BuildRequires: libnl3-devel
BuildRequires: libselinux-devel
BuildRequires: dnsmasq >= 2.41
BuildRequires: iptables
BuildRequires: radvd
BuildRequires: ebtables
BuildRequires: module-init-tools
BuildRequires: cyrus-sasl-devel
BuildRequires: polkit >= 0.112
# For mount/umount in FS driver
BuildRequires: util-linux
%if %{with_qemu}
# For managing ACLs
BuildRequires: libacl-devel
# From QEMU RPMs
BuildRequires: /usr/bin/qemu-img
%endif
# For LVM drivers
BuildRequires: lvm2
# For pool type=iscsi
BuildRequires: iscsi-initiator-utils
%if %{with_storage_iscsi_direct}
# For pool type=iscsi-direct
BuildRequires: libiscsi-devel
%endif
# For disk driver
BuildRequires: parted-devel
# For Multipath support
BuildRequires: device-mapper-devel
# For XFS reflink clone support
BuildRequires: xfsprogs-devel
%if %{with_storage_rbd}
    %if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires: librados-devel
BuildRequires: librbd-devel
    %else
BuildRequires: librados2-devel
BuildRequires: librbd1-devel
    %endif
%endif
%if %{with_storage_gluster}
BuildRequires: glusterfs-api-devel >= 3.4.1
BuildRequires: glusterfs-devel >= 3.4.1
%endif
%if %{with_storage_sheepdog}
BuildRequires: sheepdog
%endif
%if %{with_storage_zfs}
# Support any conforming implementation of zfs. On stock Fedora
# this is zfs-fuse, but could be zfsonlinux upstream RPMs
BuildRequires: /sbin/zfs
BuildRequires: /sbin/zpool
%endif
%if %{with_numactl}
# For QEMU/LXC numa info
BuildRequires: numactl-devel
%endif
BuildRequires: libcap-ng-devel >= 0.5.0
%if %{with_fuse}
BuildRequires: fuse-devel >= 2.8.6
%endif
%if %{with_libssh2}
BuildRequires: libssh2-devel >= 1.3.0
%endif

BuildRequires: netcf-devel >= 0.2.2
%if %{with_esx}
BuildRequires: libcurl-devel
%endif
%if %{with_hyperv}
BuildRequires: libwsman-devel >= 2.2.3
%endif
BuildRequires: audit-libs-devel
# we need /usr/sbin/dtrace
BuildRequires: systemtap-sdt-devel

# For mount/umount in FS driver
BuildRequires: util-linux
# For showmount in FS driver (netfs discovery)
BuildRequires: nfs-utils

# Communication with the firewall and polkit daemons use DBus
BuildRequires: dbus-devel

# Fedora build root suckage
BuildRequires: gawk

# For storage wiping with different algorithms
BuildRequires: scrub

%if %{with_numad}
BuildRequires: numad
%endif

%if %{with_wireshark}
BuildRequires: wireshark-devel >= 2.4.0
%endif

%if %{with_libssh}
BuildRequires: libssh-devel >= 0.7.0
%endif

%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires: rpcgen
BuildRequires: libtirpc-devel
%endif

%if %{with_firewalld_zone}
BuildRequires: firewalld-filesystem
%endif

Provides: bundled(gnulib)

%description
Libvirt is a C toolkit to interact with the virtualization capabilities
of recent versions of Linux (and other OSes). The main package includes
the libvirtd server exporting the virtualization support.

%package docs
Summary: API reference and website documentation

%description docs
Includes the API reference for the libvirt C library, and a complete
copy of the libvirt.org website documentation.

%package daemon
Summary: Server side daemon and supporting files for libvirt library

# All runtime requirements for the libvirt package (runtime requrements
# for subpackages are listed later in those subpackages)

# The client side, i.e. shared libs are in a subpackage
Requires: %{name}-libs = %{version}-%{release}

# (client invokes 'nc' against the UNIX socket on the server)
Requires: /usr/bin/nc

# for modprobe of pci devices
Requires: module-init-tools

# for /sbin/ip & /sbin/tc
Requires: iproute
# tc is provided by iproute-tc since at least Fedora 26
%if 0%{?fedora} || 0%{?rhel} > 7
Requires: iproute-tc
%endif

Requires: polkit >= 0.112
%ifarch %{ix86} x86_64 ia64
# For virConnectGetSysinfo
Requires: dmidecode
%endif
# For service management
Requires(post): systemd-units
Requires(post): systemd-sysv
Requires(preun): systemd-units
Requires(postun): systemd-units
%if %{with_numad}
Requires: numad
%endif
# libvirtd depends on 'messagebus' service
Requires: dbus
# For uid creation during pre
Requires(pre): shadow-utils

%description daemon
Server side daemon required to manage the virtualization capabilities
of recent versions of Linux. Requires a hypervisor specific sub-RPM
for specific drivers.

%package daemon-config-network
Summary: Default configuration files for the libvirtd daemon

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}

%description daemon-config-network
Default configuration files for setting up NAT based networking

%package daemon-config-nwfilter
Summary: Network filter configuration files for the libvirtd daemon

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}

%description daemon-config-nwfilter
Network filter configuration files for cleaning guest traffic

%package daemon-driver-network
Summary: Network driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: dnsmasq >= 2.41
Requires: radvd
Requires: iptables

%description daemon-driver-network
The network driver plugin for the libvirtd daemon, providing
an implementation of the virtual network APIs using the Linux
bridge capabilities.


%package daemon-driver-nwfilter
Summary: Nwfilter driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: iptables
Requires: ebtables

%description daemon-driver-nwfilter
The nwfilter driver plugin for the libvirtd daemon, providing
an implementation of the firewall APIs using the ebtables,
iptables and ip6tables capabilities


%package daemon-driver-nodedev
Summary: Nodedev driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# needed for device enumeration
Requires: systemd >= 185

%description daemon-driver-nodedev
The nodedev driver plugin for the libvirtd daemon, providing
an implementation of the node device APIs using the udev
capabilities.


%package daemon-driver-interface
Summary: Interface driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: netcf-libs >= 0.2.2

%description daemon-driver-interface
The interface driver plugin for the libvirtd daemon, providing
an implementation of the network interface APIs using the
netcf library


%package daemon-driver-secret
Summary: Secret driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-secret
The secret driver plugin for the libvirtd daemon, providing
an implementation of the secret key APIs.

%package daemon-driver-storage-core
Summary: Storage driver plugin including base backends for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: nfs-utils
# For mkfs
Requires: util-linux
%if %{with_qemu}
# From QEMU RPMs
Requires: /usr/bin/qemu-img
%endif
%if !%{with_storage_rbd}
Obsoletes: libvirt-daemon-driver-storage-rbd < %{version}-%{release}
%endif

%description daemon-driver-storage-core
The storage driver plugin for the libvirtd daemon, providing
an implementation of the storage APIs using files, local disks, LVM, SCSI,
iSCSI, and multipath storage.

%package daemon-driver-storage-logical
Summary: Storage driver plugin for lvm volumes
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: lvm2

%description daemon-driver-storage-logical
The storage driver backend adding implementation of the storage APIs for block
volumes using lvm.


%package daemon-driver-storage-disk
Summary: Storage driver plugin for disk
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: parted
Requires: device-mapper

%description daemon-driver-storage-disk
The storage driver backend adding implementation of the storage APIs for block
volumes using the host disks.


%package daemon-driver-storage-scsi
Summary: Storage driver plugin for local scsi devices
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-storage-scsi
The storage driver backend adding implementation of the storage APIs for scsi
host devices.


%package daemon-driver-storage-iscsi
Summary: Storage driver plugin for iscsi
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: iscsi-initiator-utils

%description daemon-driver-storage-iscsi
The storage driver backend adding implementation of the storage APIs for iscsi
volumes using the host iscsi stack.


%if %{with_storage_iscsi_direct}
%package daemon-driver-storage-iscsi-direct
Summary: Storage driver plugin for iscsi-direct
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: libiscsi

%description daemon-driver-storage-iscsi-direct
The storage driver backend adding implementation of the storage APIs for iscsi
volumes using libiscsi direct connection.
%endif


%package daemon-driver-storage-mpath
Summary: Storage driver plugin for multipath volumes
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: device-mapper

%description daemon-driver-storage-mpath
The storage driver backend adding implementation of the storage APIs for
multipath storage using device mapper.


%if %{with_storage_gluster}
%package daemon-driver-storage-gluster
Summary: Storage driver plugin for gluster
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
    %if 0%{?fedora}
Requires: glusterfs-client >= 2.0.1
    %endif
    %if (0%{?fedora} || 0%{?with_storage_gluster})
Requires: /usr/sbin/gluster
    %endif

%description daemon-driver-storage-gluster
The storage driver backend adding implementation of the storage APIs for gluster
volumes using libgfapi.
%endif


%if %{with_storage_rbd}
%package daemon-driver-storage-rbd
Summary: Storage driver plugin for rbd
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-storage-rbd
The storage driver backend adding implementation of the storage APIs for rbd
volumes using the ceph protocol.
%endif


%if %{with_storage_sheepdog}
%package daemon-driver-storage-sheepdog
Summary: Storage driver plugin for sheepdog
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: sheepdog

%description daemon-driver-storage-sheepdog
The storage driver backend adding implementation of the storage APIs for
sheepdog volumes using.
%endif


%if %{with_storage_zfs}
%package daemon-driver-storage-zfs
Summary: Storage driver plugin for ZFS
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# Support any conforming implementation of zfs
Requires: /sbin/zfs
Requires: /sbin/zpool

%description daemon-driver-storage-zfs
The storage driver backend adding implementation of the storage APIs for
ZFS volumes.
%endif


%package daemon-driver-storage
Summary: Storage driver plugin including all backends for the libvirtd daemon
Requires: libvirt-daemon-driver-storage-core = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-disk = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-logical = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-scsi = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-iscsi = %{version}-%{release}
Requires: libvirt-daemon-driver-storage-mpath = %{version}-%{release}
%if %{with_storage_iscsi_direct}
Requires: libvirt-daemon-driver-storage-iscsi-direct = %{version}-%{release}
%endif
%if %{with_storage_gluster}
Requires: libvirt-daemon-driver-storage-gluster = %{version}-%{release}
%endif
%if %{with_storage_rbd}
Requires: libvirt-daemon-driver-storage-rbd = %{version}-%{release}
%endif
%if %{with_storage_sheepdog}
Requires: libvirt-daemon-driver-storage-sheepdog = %{version}-%{release}
%endif
%if %{with_storage_zfs}
Requires: libvirt-daemon-driver-storage-zfs = %{version}-%{release}
%endif

%description daemon-driver-storage
The storage driver plugin for the libvirtd daemon, providing
an implementation of the storage APIs using LVM, iSCSI,
parted and more.


%if %{with_qemu}
%package daemon-driver-qemu
Summary: QEMU driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Requires: /usr/bin/qemu-img
# For image compression
Requires: gzip
Requires: bzip2
Requires: lzop
Requires: xz
    %if 0%{?fedora} || 0%{?rhel} > 7
Requires: systemd-container
    %endif

%description daemon-driver-qemu
The qemu driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
QEMU
%endif


%if %{with_lxc}
%package daemon-driver-lxc
Summary: LXC driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
# There really is a hard cross-driver dependency here
Requires: libvirt-daemon-driver-network = %{version}-%{release}
    %if 0%{?fedora} || 0%{?rhel} > 7
Requires: systemd-container
    %endif

%description daemon-driver-lxc
The LXC driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
the Linux kernel
%endif


%if %{with_vbox}
%package daemon-driver-vbox
Summary: VirtualBox driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}

%description daemon-driver-vbox
The vbox driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
VirtualBox
%endif


%if %{with_libxl}
%package daemon-driver-libxl
Summary: Libxl driver plugin for the libvirtd daemon
Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-libs = %{version}-%{release}
Obsoletes: libvirt-daemon-driver-xen < 4.3.0

%description daemon-driver-libxl
The Libxl driver plugin for the libvirtd daemon, providing
an implementation of the hypervisor driver APIs using
Libxl
%endif



%if %{with_qemu_tcg}
%package daemon-qemu
Summary: Server side daemon & driver required to run QEMU guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: qemu

%description daemon-qemu
Server side daemon and driver required to manage the virtualization
capabilities of the QEMU TCG emulators
%endif


%if %{with_qemu_kvm}
%package daemon-kvm
Summary: Server side daemon & driver required to run KVM guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-qemu = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: qemu-kvm

%description daemon-kvm
Server side daemon and driver required to manage the virtualization
capabilities of the KVM hypervisor
%endif


%if %{with_lxc}
%package daemon-lxc
Summary: Server side daemon & driver required to run LXC guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-lxc = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}

%description daemon-lxc
Server side daemon and driver required to manage the virtualization
capabilities of LXC
%endif


%if %{with_libxl}
%package daemon-xen
Summary: Server side daemon & driver required to run XEN guests

Requires: libvirt-daemon = %{version}-%{release}
    %if %{with_libxl}
Requires: libvirt-daemon-driver-libxl = %{version}-%{release}
    %endif
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}
Requires: xen

%description daemon-xen
Server side daemon and driver required to manage the virtualization
capabilities of XEN
%endif

%if %{with_vbox}
%package daemon-vbox
Summary: Server side daemon & driver required to run VirtualBox guests

Requires: libvirt-daemon = %{version}-%{release}
Requires: libvirt-daemon-driver-vbox = %{version}-%{release}
Requires: libvirt-daemon-driver-interface = %{version}-%{release}
Requires: libvirt-daemon-driver-network = %{version}-%{release}
Requires: libvirt-daemon-driver-nodedev = %{version}-%{release}
Requires: libvirt-daemon-driver-nwfilter = %{version}-%{release}
Requires: libvirt-daemon-driver-secret = %{version}-%{release}
Requires: libvirt-daemon-driver-storage = %{version}-%{release}

%description daemon-vbox
Server side daemon and driver required to manage the virtualization
capabilities of VirtualBox
%endif

%package client
Summary: Client side utilities of the libvirt library
Requires: %{name}-libs = %{version}-%{release}
Requires: readline
Requires: ncurses
# Needed by /usr/libexec/libvirt-guests.sh script.
Requires: gettext
# Needed by virt-pki-validate script.
Requires: gnutls-utils
%if %{with_bash_completion}
Requires: %{name}-bash-completion = %{version}-%{release}
%endif

%description client
The client binaries needed to access the virtualization
capabilities of recent versions of Linux (and other OSes).

%package libs
Summary: Client side libraries
# So remote clients can access libvirt over SSH tunnel
Requires: cyrus-sasl
# Needed by default sasl.conf - no onerous extra deps, since
# 100's of other things on a system already pull in krb5-libs
Requires: cyrus-sasl-gssapi

%description libs
Shared libraries for accessing the libvirt daemon.

%package admin
Summary: Set of tools to control libvirt daemon
Requires: %{name}-libs = %{version}-%{release}
Requires: readline
%if %{with_bash_completion}
Requires: %{name}-bash-completion = %{version}-%{release}
%endif

%description admin
The client side utilities to control the libvirt daemon.

%if %{with_bash_completion}
%package bash-completion
Summary: Bash completion script

%description bash-completion
Bash completion script stub.
%endif

%if %{with_wireshark}
%package wireshark
Summary: Wireshark dissector plugin for libvirt RPC transactions
Requires: wireshark >= 2.4.0
Requires: %{name}-libs = %{version}-%{release}

%description wireshark
Wireshark dissector plugin for better analysis of libvirt RPC traffic.
%endif

%if %{with_lxc}
%package login-shell
Summary: Login shell for connecting users to an LXC container
Requires: %{name}-libs = %{version}-%{release}

%description login-shell
Provides the set-uid virt-login-shell binary that is used to
connect a user to an LXC container when they login, by switching
namespaces.
%endif

%package devel
Summary: Libraries, includes, etc. to compile with the libvirt library
Requires: %{name}-libs = %{version}-%{release}
Requires: pkgconfig

%description devel
Include header files & development libraries for the libvirt C library.

%if %{with_sanlock}
%package lock-sanlock
Summary: Sanlock lock manager plugin for QEMU driver
Requires: sanlock >= 2.4
#for virt-sanlock-cleanup require augeas
Requires: augeas
Requires: %{name}-daemon = %{version}-%{release}
Requires: %{name}-libs = %{version}-%{release}

%description lock-sanlock
Includes the Sanlock lock manager plugin for the QEMU
driver
%endif

%package nss
Summary: Libvirt plugin for Name Service Switch
Requires: libvirt-daemon-driver-network = %{version}-%{release}

%description nss
Libvirt plugin for NSS for translating domain names into IP addresses.


%prep

%autosetup -S git_am -N

# "make dist" replaces all symlinks with a copy of the linked files;
# we need to replace all of them with the original symlinks
echo "Restoring symlinks"
while read lnk target; do
    if [ -e $lnk ]; then
        rm -rf $lnk
        ln -s $target $lnk
    fi
done <%{_sourcedir}/symlinks || exit 1
git add .
git commit -q -a --author 'rpm-build <rpm-build>' -m symlinks


git config gc.auto 0

%autopatch

%build
%if ! %{supported_platform}
echo "This RPM requires either Fedora >= %{min_fedora} or RHEL >= %{min_rhel}"
exit 1
%endif

%if %{with_qemu}
    %define arg_qemu --with-qemu
%else
    %define arg_qemu --without-qemu
%endif

%if %{with_openvz}
    %define arg_openvz --with-openvz
%else
    %define arg_openvz --without-openvz
%endif

%if %{with_lxc}
    %define arg_lxc --with-lxc
    %define arg_login_shell --with-login-shell
%else
    %define arg_lxc --without-lxc
    %define arg_login_shell --without-login-shell
%endif

%if %{with_vbox}
    %define arg_vbox --with-vbox
%else
    %define arg_vbox --without-vbox
%endif

%if %{with_libxl}
    %define arg_libxl --with-libxl
%else
    %define arg_libxl --without-libxl
%endif

%if %{with_esx}
    %define arg_esx --with-esx
%else
    %define arg_esx --without-esx
%endif

%if %{with_hyperv}
    %define arg_hyperv --with-hyperv
%else
    %define arg_hyperv --without-hyperv
%endif

%if %{with_vmware}
    %define arg_vmware --with-vmware
%else
    %define arg_vmware --without-vmware
%endif

%if %{with_storage_rbd}
    %define arg_storage_rbd --with-storage-rbd
%else
    %define arg_storage_rbd --without-storage-rbd
%endif

%if %{with_storage_sheepdog}
    %define arg_storage_sheepdog --with-storage-sheepdog
%else
    %define arg_storage_sheepdog --without-storage-sheepdog
%endif

%if %{with_storage_gluster}
    %define arg_storage_gluster --with-storage-gluster
%else
    %define arg_storage_gluster --without-storage-gluster
%endif

%if %{with_storage_zfs}
    %define arg_storage_zfs --with-storage-zfs
%else
    %define arg_storage_zfs --without-storage-zfs
%endif

%if %{with_numactl}
    %define arg_numactl --with-numactl
%else
    %define arg_numactl --without-numactl
%endif

%if %{with_numad}
    %define arg_numad --with-numad
%else
    %define arg_numad --without-numad
%endif

%if %{with_fuse}
    %define arg_fuse --with-fuse
%else
    %define arg_fuse --without-fuse
%endif

%if %{with_sanlock}
    %define arg_sanlock --with-sanlock
%else
    %define arg_sanlock --without-sanlock
%endif

%if %{with_firewalld}
    %define arg_firewalld --with-firewalld
%else
    %define arg_firewalld --without-firewalld
%endif

%if %{with_firewalld_zone}
    %define arg_firewalld_zone --with-firewalld-zone
%else
    %define arg_firewalld_zone --without-firewalld-zone
%endif

%if %{with_wireshark}
    %define arg_wireshark --with-wireshark-dissector
%else
    %define arg_wireshark --without-wireshark-dissector
%endif

%if %{with_storage_iscsi_direct}
    %define arg_storage_iscsi_direct --with-storage-iscsi-direct
%else
    %define arg_storage_iscsi_direct --without-storage-iscsi-direct
%endif

%define when  %(date +"%%F-%%T")
%define where %(hostname)
%define who   %{?packager}%{!?packager:Unknown}
%define arg_packager --with-packager="%{who}, %{when}, %{where}"
%define arg_packager_version --with-packager-version="%{release}"

%define arg_selinux_mount --with-selinux-mount="/sys/fs/selinux"

# place macros above and build commands below this comment

export SOURCE_DATE_EPOCH=$(stat --printf='%Y' %{_specdir}/%{name}.spec)

%if 0%{?enable_autotools}
 autoreconf -if
%endif

rm -f po/stamp-po

%define _configure ../configure
mkdir %{_vpath_builddir}
cd %{_vpath_builddir}

%configure --enable-dependency-tracking \
           --with-runstatedir=%{_rundir} \
           %{?arg_qemu} \
           %{?arg_openvz} \
           %{?arg_lxc} \
           %{?arg_vbox} \
           %{?arg_libxl} \
           --with-sasl \
           --with-polkit \
           --with-libvirtd \
           %{?arg_esx} \
           %{?arg_hyperv} \
           %{?arg_vmware} \
           --without-vz \
           --without-bhyve \
           --with-remote-default-mode=legacy \
           --with-interface \
           --with-network \
           --with-storage-fs \
           --with-storage-lvm \
           --with-storage-iscsi \
           %{?arg_storage_iscsi_direct} \
           --with-storage-scsi \
           --with-storage-disk \
           --with-storage-mpath \
           %{?arg_storage_rbd} \
           %{?arg_storage_sheepdog} \
           %{?arg_storage_gluster} \
           %{?arg_storage_zfs} \
           --without-storage-vstorage \
           %{?arg_numactl} \
           %{?arg_numad} \
           --with-capng \
           %{?arg_fuse} \
           --with-netcf \
           --with-selinux \
           %{?arg_selinux_mount} \
           --without-apparmor \
           --without-hal \
           --with-udev \
           --with-yajl \
           %{?arg_sanlock} \
           --with-libpcap \
           --with-macvtap \
           --with-audit \
           --with-dtrace \
           --with-driver-modules \
           %{?arg_firewalld} \
           %{?arg_firewalld_zone} \
           %{?arg_wireshark} \
           --without-pm-utils \
           --with-nss-plugin \
           %{arg_packager} \
           %{arg_packager_version} \
           --with-qemu-user=%{qemu_user} \
           --with-qemu-group=%{qemu_group} \
           --with-tls-priority=%{tls_priority} \
           %{?enable_werror} \
           --enable-expensive-tests \
           --with-init-script=systemd \
           %{?arg_login_shell}
make %{?_smp_mflags} V=1

%install
rm -fr %{buildroot}

export SOURCE_DATE_EPOCH=$(stat --printf='%Y' %{_specdir}/%{name}.spec)

cd %{_vpath_builddir}
%make_install %{?_smp_mflags} SYSTEMD_UNIT_DIR=%{_unitdir} V=1

rm -f $RPM_BUILD_ROOT%{_libdir}/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/lock-driver/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/lock-driver/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/connection-driver/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/connection-driver/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-backend/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-backend/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-file/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/libvirt/storage-file/*.a
%if %{with_wireshark}
rm -f $RPM_BUILD_ROOT%{wireshark_plugindir}/libvirt.la
%endif

install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/lib/libvirt/dnsmasq/
# We don't want to install /etc/libvirt/qemu/networks in the main %files list
# because if the admin wants to delete the default network completely, we don't
# want to end up re-incarnating it on every RPM upgrade.
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/
cp $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml \
   $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/default.xml
# libvirt saves this file with mode 0600
chmod 0600 $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml

# nwfilter files are installed in /usr/share/libvirt and copied to /etc in %post
# to avoid verification errors on changed files in /etc
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/libvirt/nwfilter/
cp -a $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/nwfilter/*.xml \
    $RPM_BUILD_ROOT%{_datadir}/libvirt/nwfilter/
# libvirt saves these files with mode 600
chmod 600 $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/nwfilter/*.xml

# Strip auto-generated UUID - we need it generated per-install
sed -i -e "/<uuid>/d" $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/default.xml
%if ! %{with_qemu}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_qemu.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%endif
%find_lang %{name}

%if ! %{with_sanlock}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirt_sanlock.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirt_sanlock.aug
%endif

%if ! %{with_lxc}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_lxc.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%endif

%if ! %{with_qemu}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.qemu
%endif
%if ! %{with_lxc}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/lxc.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.lxc
%endif
%if ! %{with_libxl}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/libxl.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.libxl
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_libxl.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_libxl.aug
%endif

# Copied into libvirt-docs subpackage eventually
mv $RPM_BUILD_ROOT%{_datadir}/doc/libvirt libvirt-docs

%ifarch %{power64} s390x x86_64 ia64 alpha sparc64
mv $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_probes.stp \
   $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_probes-64.stp

    %if %{with_qemu}
mv $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_qemu_probes.stp \
   $RPM_BUILD_ROOT%{_datadir}/systemtap/tapset/libvirt_qemu_probes-64.stp
    %endif
%endif

%check
# The gnulib's test test-nonblocking-pipe.sh depends on timing and fails
# on AArch64. Let's just disable it until we get rid of gnulib completely.
for t in gnulib/tests/test-nonblocking-pipe.sh; do
    rm -f $t
    printf '#!/bin/sh\nexit 77\n' > $t
    chmod a+x $t
done

cd %{_vpath_builddir}
if ! make %{?_smp_mflags} check VIR_TEST_DEBUG=1
then
  cat tests/test-suite.log || true
  exit 1
fi

%post libs
%if 0%{?rhel} == 7
/sbin/ldconfig
%endif

%postun libs
%if 0%{?rhel} == 7
/sbin/ldconfig
%endif

%pre daemon
# 'libvirt' group is just to allow password-less polkit access to
# libvirtd. The uid number is irrelevant, so we use dynamic allocation
# described at the above link.
getent group libvirt >/dev/null || groupadd -r libvirt

exit 0

%post daemon

%systemd_post virtlockd.socket virtlockd-admin.socket
%systemd_post virtlogd.socket virtlogd-admin.socket
%systemd_post libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
%systemd_post libvirtd-tcp.socket libvirtd-tls.socket
%systemd_post libvirtd.service

# request daemon restart in posttrans
mkdir -p %{_localstatedir}/lib/rpm-state/libvirt || :
touch %{_localstatedir}/lib/rpm-state/libvirt/restart || :

%preun daemon
%systemd_preun libvirtd.service
%systemd_preun libvirtd-tcp.socket libvirtd-tls.socket
%systemd_preun libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
%systemd_preun virtlogd.socket virtlogd-admin.socket virtlogd.service
%systemd_preun virtlockd.socket virtlockd-admin.socket virtlockd.service

%postun daemon
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    /bin/systemctl reload-or-try-restart virtlockd.service >/dev/null 2>&1 || :
    /bin/systemctl reload-or-try-restart virtlogd.service >/dev/null 2>&1 || :
fi

# In upgrade scenario we must explicitly enable virtlockd/virtlogd
# sockets, if libvirtd is already enabled and start them if
# libvirtd is running, otherwise you'll get failures to start
# guests
%triggerpostun daemon -- libvirt-daemon < 1.3.0
if [ $1 -ge 1 ] ; then
    /bin/systemctl is-enabled libvirtd.service 1>/dev/null 2>&1 &&
        /bin/systemctl enable virtlogd.socket virtlogd-admin.socket || :
    /bin/systemctl is-active libvirtd.service 1>/dev/null 2>&1 &&
        /bin/systemctl start virtlogd.socket virtlogd-admin.socket || :
fi

%posttrans daemon
if [ -f %{_localstatedir}/lib/rpm-state/libvirt/restart ]; then
    # See if user has previously modified their install to
    # tell libvirtd to use --listen
    grep -E '^LIBVIRTD_ARGS=.*--listen' /etc/sysconfig/libvirtd 1>/dev/null 2>&1
    if test $? = 0
    then
        # Then lets keep honouring --listen and *not* use
        # systemd socket activation, because switching things
        # might confuse mgmt tool like puppet/ansible that
        # expect the old style libvirtd
        /bin/systemctl mask libvirtd.socket >/dev/null 2>&1 || :
        /bin/systemctl mask libvirtd-ro.socket >/dev/null 2>&1 || :
        /bin/systemctl mask libvirtd-admin.socket >/dev/null 2>&1 || :
        /bin/systemctl mask libvirtd-tls.socket >/dev/null 2>&1 || :
        /bin/systemctl mask libvirtd-tcp.socket >/dev/null 2>&1 || :
    else
        # Old libvirtd owns the sockets and will delete them on
        # shutdown. Can't use a try-restart as libvirtd will simply
        # own the sockets again when it comes back up. Thus we must
        # do this particular ordering, so that we get libvirtd
        # running with socket activation in use
        /bin/systemctl is-active libvirtd.service 1>/dev/null 2>&1
        if test $? = 0
        then
            /bin/systemctl stop libvirtd.service >/dev/null 2>&1 || :

            /bin/systemctl try-restart libvirtd.socket >/dev/null 2>&1 || :
            /bin/systemctl try-restart libvirtd-ro.socket >/dev/null 2>&1 || :
            /bin/systemctl try-restart libvirtd-admin.socket >/dev/null 2>&1 || :

            /bin/systemctl start libvirtd.service >/dev/null 2>&1 || :
        fi
    fi
fi
rm -rf %{_localstatedir}/lib/rpm-state/libvirt || :

%post daemon-driver-network
%if %{with_firewalld_zone}
    %firewalld_reload
%endif

%postun daemon-driver-network
%if %{with_firewalld_zone}
    %firewalld_reload
%endif

%post daemon-config-network
if test $1 -eq 1 && test ! -f %{_sysconfdir}/libvirt/qemu/networks/default.xml ; then
    # see if the network used by default network creates a conflict,
    # and try to resolve it
    # NB: 192.168.122.0/24 is used in the default.xml template file;
    # do not modify any of those values here without also modifying
    # them in the template.
    orig_sub=122
    sub=${orig_sub}
    nl='
'
    routes="${nl}$(ip route show | cut -d' ' -f1)${nl}"
    case ${routes} in
      *"${nl}192.168.${orig_sub}.0/24${nl}"*)
        # there was a match, so we need to look for an unused subnet
        for new_sub in $(seq 124 254); do
          case ${routes} in
          *"${nl}192.168.${new_sub}.0/24${nl}"*)
            ;;
          *)
            sub=$new_sub
            break;
            ;;
          esac
        done
        ;;
      *)
        ;;
    esac

    UUID=`/usr/bin/uuidgen`
    sed -e "s/${orig_sub}/${sub}/g" \
        -e "s,</name>,</name>\n  <uuid>$UUID</uuid>," \
         < %{_datadir}/libvirt/networks/default.xml \
         > %{_sysconfdir}/libvirt/qemu/networks/default.xml
    ln -s ../default.xml %{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml
    # libvirt saves this file with mode 0600
    chmod 0600 %{_sysconfdir}/libvirt/qemu/networks/default.xml

    # Make sure libvirt picks up the new network defininiton
    mkdir -p %{_localstatedir}/lib/rpm-state/libvirt || :
    touch %{_localstatedir}/lib/rpm-state/libvirt/restart || :
fi

%posttrans daemon-config-network
if [ -f %{_localstatedir}/lib/rpm-state/libvirt/restart ]; then
    /bin/systemctl try-restart libvirtd.service >/dev/null 2>&1 || :
fi
rm -rf %{_localstatedir}/lib/rpm-state/libvirt || :

%post daemon-config-nwfilter
cp %{_datadir}/libvirt/nwfilter/*.xml %{_sysconfdir}/libvirt/nwfilter/
# libvirt saves these files with mode 600
chmod 600 %{_sysconfdir}/libvirt/nwfilter/*.xml
# Make sure libvirt picks up the new nwfilter defininitons
mkdir -p %{_localstatedir}/lib/rpm-state/libvirt || :
touch %{_localstatedir}/lib/rpm-state/libvirt/restart || :

%posttrans daemon-config-nwfilter
if [ -f %{_localstatedir}/lib/rpm-state/libvirt/restart ]; then
    /bin/systemctl try-restart libvirtd.service >/dev/null 2>&1 || :
fi
rm -rf %{_localstatedir}/lib/rpm-state/libvirt || :


%if %{with_qemu}
%pre daemon-driver-qemu
# We want soft static allocation of well-known ids, as disk images
# are commonly shared across NFS mounts by id rather than name; see
# https://fedoraproject.org/wiki/Packaging:UsersAndGroups
getent group kvm >/dev/null || groupadd -f -g 36 -r kvm
getent group qemu >/dev/null || groupadd -f -g 107 -r qemu
if ! getent passwd qemu >/dev/null; then
  if ! getent passwd 107 >/dev/null; then
    useradd -r -u 107 -g qemu -G kvm -d / -s /sbin/nologin -c "qemu user" qemu
  else
    useradd -r -g qemu -G kvm -d / -s /sbin/nologin -c "qemu user" qemu
  fi
fi
exit 0
%endif

%preun client

%systemd_preun libvirt-guests.service

%post client
%systemd_post libvirt-guests.service

%postun client
%systemd_postun libvirt-guests.service

%if %{with_lxc}
%pre login-shell
getent group virtlogin >/dev/null || groupadd -r virtlogin
exit 0
%endif

%files

%files docs
%doc AUTHORS ChangeLog NEWS README README.md
%doc %{_vpath_builddir}/libvirt-docs/*

%files daemon

%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/

%{_unitdir}/libvirtd.service
%{_unitdir}/libvirtd.socket
%{_unitdir}/libvirtd-ro.socket
%{_unitdir}/libvirtd-admin.socket
%{_unitdir}/libvirtd-tcp.socket
%{_unitdir}/libvirtd-tls.socket
%{_unitdir}/virtproxyd.service
%{_unitdir}/virtproxyd.socket
%{_unitdir}/virtproxyd-ro.socket
%{_unitdir}/virtproxyd-admin.socket
%{_unitdir}/virtproxyd-tcp.socket
%{_unitdir}/virtproxyd-tls.socket
%{_unitdir}/virt-guest-shutdown.target
%{_unitdir}/virtlogd.service
%{_unitdir}/virtlogd.socket
%{_unitdir}/virtlogd-admin.socket
%{_unitdir}/virtlockd.service
%{_unitdir}/virtlockd.socket
%{_unitdir}/virtlockd-admin.socket
%config(noreplace) %{_sysconfdir}/sysconfig/libvirtd
%config(noreplace) %{_sysconfdir}/sysconfig/virtlogd
%config(noreplace) %{_sysconfdir}/sysconfig/virtlockd
%config(noreplace) %{_sysconfdir}/libvirt/libvirtd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtproxyd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtlogd.conf
%config(noreplace) %{_sysconfdir}/libvirt/virtlockd.conf
%config(noreplace) %{_sysconfdir}/sasl2/libvirt.conf
%config(noreplace) %{_prefix}/lib/sysctl.d/60-libvirtd.conf

%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd
%dir %{_datadir}/libvirt/

%ghost %dir %{_rundir}/libvirt/

%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/images/
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/filesystems/
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/boot/
%dir %attr(0711, root, root) %{_localstatedir}/cache/libvirt/


%dir %attr(0755, root, root) %{_libdir}/libvirt/
%dir %attr(0755, root, root) %{_libdir}/libvirt/connection-driver/
%dir %attr(0755, root, root) %{_libdir}/libvirt/lock-driver
%attr(0755, root, root) %{_libdir}/libvirt/lock-driver/lockd.so

%{_datadir}/augeas/lenses/libvirtd.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd.aug
%{_datadir}/augeas/lenses/virtlogd.aug
%{_datadir}/augeas/lenses/tests/test_virtlogd.aug
%{_datadir}/augeas/lenses/virtlockd.aug
%{_datadir}/augeas/lenses/tests/test_virtlockd.aug
%{_datadir}/augeas/lenses/virtproxyd.aug
%{_datadir}/augeas/lenses/tests/test_virtproxyd.aug
%{_datadir}/augeas/lenses/libvirt_lockd.aug
%if %{with_qemu}
%{_datadir}/augeas/lenses/tests/test_libvirt_lockd.aug
%endif

%{_datadir}/polkit-1/actions/org.libvirt.unix.policy
%{_datadir}/polkit-1/actions/org.libvirt.api.policy
%{_datadir}/polkit-1/rules.d/50-libvirt.rules

%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/

%attr(0755, root, root) %{_libexecdir}/libvirt_iohelper

%attr(0755, root, root) %{_sbindir}/libvirtd
%attr(0755, root, root) %{_sbindir}/virtproxyd
%attr(0755, root, root) %{_sbindir}/virtlogd
%attr(0755, root, root) %{_sbindir}/virtlockd

%{_mandir}/man8/libvirtd.8*
%{_mandir}/man8/virtlogd.8*
%{_mandir}/man8/virtlockd.8*
%{_mandir}/man7/virkey*.7*

%files daemon-config-network
%dir %{_datadir}/libvirt/networks/
%{_datadir}/libvirt/networks/default.xml
%ghost %{_sysconfdir}/libvirt/qemu/networks/default.xml
%ghost %{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml

%files daemon-config-nwfilter
%dir %{_datadir}/libvirt/nwfilter/
%{_datadir}/libvirt/nwfilter/*.xml
%ghost %{_sysconfdir}/libvirt/nwfilter/*.xml

%files daemon-driver-interface
%config(noreplace) %{_sysconfdir}/libvirt/virtinterfaced.conf
%{_datadir}/augeas/lenses/virtinterfaced.aug
%{_datadir}/augeas/lenses/tests/test_virtinterfaced.aug
%{_unitdir}/virtinterfaced.service
%{_unitdir}/virtinterfaced.socket
%{_unitdir}/virtinterfaced-ro.socket
%{_unitdir}/virtinterfaced-admin.socket
%attr(0755, root, root) %{_sbindir}/virtinterfaced
%{_libdir}/%{name}/connection-driver/libvirt_driver_interface.so

%files daemon-driver-network
%config(noreplace) %{_sysconfdir}/libvirt/virtnetworkd.conf
%{_datadir}/augeas/lenses/virtnetworkd.aug
%{_datadir}/augeas/lenses/tests/test_virtnetworkd.aug
%{_unitdir}/virtnetworkd.service
%{_unitdir}/virtnetworkd.socket
%{_unitdir}/virtnetworkd-ro.socket
%{_unitdir}/virtnetworkd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnetworkd
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/autostart
%ghost %dir %{_rundir}/libvirt/network/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/network/
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/dnsmasq/
%attr(0755, root, root) %{_libexecdir}/libvirt_leaseshelper
%{_libdir}/%{name}/connection-driver/libvirt_driver_network.so

%if %{with_firewalld_zone}
%{_prefix}/lib/firewalld/zones/libvirt.xml
%endif

%files daemon-driver-nodedev
%config(noreplace) %{_sysconfdir}/libvirt/virtnodedevd.conf
%{_datadir}/augeas/lenses/virtnodedevd.aug
%{_datadir}/augeas/lenses/tests/test_virtnodedevd.aug
%{_unitdir}/virtnodedevd.service
%{_unitdir}/virtnodedevd.socket
%{_unitdir}/virtnodedevd-ro.socket
%{_unitdir}/virtnodedevd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnodedevd
%{_libdir}/%{name}/connection-driver/libvirt_driver_nodedev.so

%files daemon-driver-nwfilter
%config(noreplace) %{_sysconfdir}/libvirt/virtnwfilterd.conf
%{_datadir}/augeas/lenses/virtnwfilterd.aug
%{_datadir}/augeas/lenses/tests/test_virtnwfilterd.aug
%{_unitdir}/virtnwfilterd.service
%{_unitdir}/virtnwfilterd.socket
%{_unitdir}/virtnwfilterd-ro.socket
%{_unitdir}/virtnwfilterd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtnwfilterd
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/nwfilter/
%ghost %dir %{_rundir}/libvirt/network/
%{_libdir}/%{name}/connection-driver/libvirt_driver_nwfilter.so

%files daemon-driver-secret
%config(noreplace) %{_sysconfdir}/libvirt/virtsecretd.conf
%{_datadir}/augeas/lenses/virtsecretd.aug
%{_datadir}/augeas/lenses/tests/test_virtsecretd.aug
%{_unitdir}/virtsecretd.service
%{_unitdir}/virtsecretd.socket
%{_unitdir}/virtsecretd-ro.socket
%{_unitdir}/virtsecretd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtsecretd
%{_libdir}/%{name}/connection-driver/libvirt_driver_secret.so

%files daemon-driver-storage

%files daemon-driver-storage-core
%config(noreplace) %{_sysconfdir}/libvirt/virtstoraged.conf
%{_datadir}/augeas/lenses/virtstoraged.aug
%{_datadir}/augeas/lenses/tests/test_virtstoraged.aug
%{_unitdir}/virtstoraged.service
%{_unitdir}/virtstoraged.socket
%{_unitdir}/virtstoraged-ro.socket
%{_unitdir}/virtstoraged-admin.socket
%attr(0755, root, root) %{_sbindir}/virtstoraged
%attr(0755, root, root) %{_libexecdir}/libvirt_parthelper
%{_libdir}/%{name}/connection-driver/libvirt_driver_storage.so
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_fs.so
%{_libdir}/%{name}/storage-file/libvirt_storage_file_fs.so

%files daemon-driver-storage-disk
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_disk.so

%files daemon-driver-storage-logical
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_logical.so

%files daemon-driver-storage-scsi
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_scsi.so

%files daemon-driver-storage-iscsi
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_iscsi.so

%if %{with_storage_iscsi_direct}
%files daemon-driver-storage-iscsi-direct
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_iscsi-direct.so
%endif

%files daemon-driver-storage-mpath
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_mpath.so

%if %{with_storage_gluster}
%files daemon-driver-storage-gluster
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_gluster.so
%{_libdir}/%{name}/storage-file/libvirt_storage_file_gluster.so
%endif

%if %{with_storage_rbd}
%files daemon-driver-storage-rbd
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_rbd.so
%endif

%if %{with_storage_sheepdog}
%files daemon-driver-storage-sheepdog
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_sheepdog.so
%endif

%if %{with_storage_zfs}
%files daemon-driver-storage-zfs
%{_libdir}/%{name}/storage-backend/libvirt_storage_backend_zfs.so
%endif

%if %{with_qemu}
%files daemon-driver-qemu
%config(noreplace) %{_sysconfdir}/libvirt/virtqemud.conf
%{_datadir}/augeas/lenses/virtqemud.aug
%{_datadir}/augeas/lenses/tests/test_virtqemud.aug
%{_unitdir}/virtqemud.service
%{_unitdir}/virtqemud.socket
%{_unitdir}/virtqemud-ro.socket
%{_unitdir}/virtqemud-admin.socket
%attr(0755, root, root) %{_sbindir}/virtqemud
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/qemu/
%config(noreplace) %{_sysconfdir}/libvirt/qemu.conf
%config(noreplace) %{_sysconfdir}/libvirt/qemu-lockd.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.qemu
%ghost %dir %{_rundir}/libvirt/qemu/
%dir %attr(0751, %{qemu_user}, %{qemu_group}) %{_localstatedir}/lib/libvirt/qemu/
%dir %attr(0750, %{qemu_user}, %{qemu_group}) %{_localstatedir}/cache/libvirt/qemu/
%{_datadir}/augeas/lenses/libvirtd_qemu.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%{_libdir}/%{name}/connection-driver/libvirt_driver_qemu.so
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/swtpm/
%dir %attr(0711, root, root) %{_localstatedir}/log/swtpm/libvirt/qemu/
%endif

%if %{with_lxc}
%files daemon-driver-lxc
%config(noreplace) %{_sysconfdir}/libvirt/virtlxcd.conf
%{_datadir}/augeas/lenses/virtlxcd.aug
%{_datadir}/augeas/lenses/tests/test_virtlxcd.aug
%{_unitdir}/virtlxcd.service
%{_unitdir}/virtlxcd.socket
%{_unitdir}/virtlxcd-ro.socket
%{_unitdir}/virtlxcd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtlxcd
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/lxc/
%config(noreplace) %{_sysconfdir}/libvirt/lxc.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.lxc
%ghost %dir %{_rundir}/libvirt/lxc/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/lxc/
%{_datadir}/augeas/lenses/libvirtd_lxc.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%attr(0755, root, root) %{_libexecdir}/libvirt_lxc
%{_libdir}/%{name}/connection-driver/libvirt_driver_lxc.so
%endif

%if %{with_libxl}
%files daemon-driver-libxl
%config(noreplace) %{_sysconfdir}/libvirt/virtxend.conf
%{_datadir}/augeas/lenses/virtxend.aug
%{_datadir}/augeas/lenses/tests/test_virtxend.aug
%{_unitdir}/virtxend.service
%{_unitdir}/virtxend.socket
%{_unitdir}/virtxend-ro.socket
%{_unitdir}/virtxend-admin.socket
%attr(0755, root, root) %{_sbindir}/virtxend
%config(noreplace) %{_sysconfdir}/libvirt/libxl.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.libxl
%config(noreplace) %{_sysconfdir}/libvirt/libxl-lockd.conf
%{_datadir}/augeas/lenses/libvirtd_libxl.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_libxl.aug
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/libxl/
%ghost %dir %{_rundir}/libvirt/libxl/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/libxl/
%{_libdir}/%{name}/connection-driver/libvirt_driver_libxl.so
%endif

%if %{with_vbox}
%files daemon-driver-vbox
%config(noreplace) %{_sysconfdir}/libvirt/virtvboxd.conf
%{_datadir}/augeas/lenses/virtvboxd.aug
%{_datadir}/augeas/lenses/tests/test_virtvboxd.aug
%{_unitdir}/virtvboxd.service
%{_unitdir}/virtvboxd.socket
%{_unitdir}/virtvboxd-ro.socket
%{_unitdir}/virtvboxd-admin.socket
%attr(0755, root, root) %{_sbindir}/virtvboxd
%{_libdir}/%{name}/connection-driver/libvirt_driver_vbox.so
%endif

%if %{with_qemu_tcg}
%files daemon-qemu
%endif

%if %{with_qemu_kvm}
%files daemon-kvm
%endif

%if %{with_lxc}
%files daemon-lxc
%endif

%if %{with_libxl}
%files daemon-xen
%endif

%if %{with_vbox}
%files daemon-vbox
%endif

%if %{with_sanlock}
%files lock-sanlock
    %if %{with_qemu}
%config(noreplace) %{_sysconfdir}/libvirt/qemu-sanlock.conf
    %endif
    %if %{with_libxl}
%config(noreplace) %{_sysconfdir}/libvirt/libxl-sanlock.conf
    %endif
%attr(0755, root, root) %{_libdir}/libvirt/lock-driver/sanlock.so
%{_datadir}/augeas/lenses/libvirt_sanlock.aug
%{_datadir}/augeas/lenses/tests/test_libvirt_sanlock.aug
%dir %attr(0770, root, sanlock) %{_localstatedir}/lib/libvirt/sanlock
%{_sbindir}/virt-sanlock-cleanup
%{_mandir}/man8/virt-sanlock-cleanup.8*
%attr(0755, root, root) %{_libexecdir}/libvirt_sanlock_helper
%endif

%files client
%{_mandir}/man1/virsh.1*
%{_mandir}/man1/virt-xml-validate.1*
%{_mandir}/man1/virt-pki-validate.1*
%{_mandir}/man1/virt-host-validate.1*
%{_bindir}/virsh
%{_bindir}/virt-xml-validate
%{_bindir}/virt-pki-validate
%{_bindir}/virt-host-validate

%{_datadir}/systemtap/tapset/libvirt_probes*.stp
%{_datadir}/systemtap/tapset/libvirt_functions.stp
%if %{with_qemu}
%{_datadir}/systemtap/tapset/libvirt_qemu_probes*.stp
%endif

%if %{with_bash_completion}
%{_datadir}/bash-completion/completions/virsh
%endif


%{_unitdir}/libvirt-guests.service
%config(noreplace) %{_sysconfdir}/sysconfig/libvirt-guests
%attr(0755, root, root) %{_libexecdir}/libvirt-guests.sh

%files libs -f %{_vpath_builddir}/%{name}.lang
%license COPYING COPYING.LESSER
%config(noreplace) %{_sysconfdir}/libvirt/libvirt.conf
%config(noreplace) %{_sysconfdir}/libvirt/libvirt-admin.conf
%{_libdir}/libvirt.so.*
%{_libdir}/libvirt-qemu.so.*
%{_libdir}/libvirt-lxc.so.*
%{_libdir}/libvirt-admin.so.*
%dir %{_datadir}/libvirt/
%dir %{_datadir}/libvirt/schemas/
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/

%{_datadir}/libvirt/schemas/basictypes.rng
%{_datadir}/libvirt/schemas/capability.rng
%{_datadir}/libvirt/schemas/cputypes.rng
%{_datadir}/libvirt/schemas/domain.rng
%{_datadir}/libvirt/schemas/domainbackup.rng
%{_datadir}/libvirt/schemas/domaincaps.rng
%{_datadir}/libvirt/schemas/domaincheckpoint.rng
%{_datadir}/libvirt/schemas/domaincommon.rng
%{_datadir}/libvirt/schemas/domainsnapshot.rng
%{_datadir}/libvirt/schemas/interface.rng
%{_datadir}/libvirt/schemas/network.rng
%{_datadir}/libvirt/schemas/networkcommon.rng
%{_datadir}/libvirt/schemas/networkport.rng
%{_datadir}/libvirt/schemas/nodedev.rng
%{_datadir}/libvirt/schemas/nwfilter.rng
%{_datadir}/libvirt/schemas/nwfilter_params.rng
%{_datadir}/libvirt/schemas/nwfilterbinding.rng
%{_datadir}/libvirt/schemas/secret.rng
%{_datadir}/libvirt/schemas/storagecommon.rng
%{_datadir}/libvirt/schemas/storagepool.rng
%{_datadir}/libvirt/schemas/storagepoolcaps.rng
%{_datadir}/libvirt/schemas/storagevol.rng

%{_datadir}/libvirt/cpu_map/*.xml

%{_datadir}/libvirt/test-screenshot.png

%files admin
%{_mandir}/man1/virt-admin.1*
%{_bindir}/virt-admin
%if %{with_bash_completion}
%{_datadir}/bash-completion/completions/virt-admin
%endif

%if %{with_bash_completion}
%files bash-completion
%{_datadir}/bash-completion/completions/vsh
%endif

%if %{with_wireshark}
%files wireshark
%{wireshark_plugindir}/libvirt.so
%endif

%files nss
%{_libdir}/libnss_libvirt.so.2
%{_libdir}/libnss_libvirt_guest.so.2

%if %{with_lxc}
%files login-shell
%attr(4750, root, virtlogin) %{_bindir}/virt-login-shell
%{_libexecdir}/virt-login-shell-helper
%config(noreplace) %{_sysconfdir}/libvirt/virt-login-shell.conf
%{_mandir}/man1/virt-login-shell.1*
%endif

%files devel
%{_libdir}/libvirt.so
%{_libdir}/libvirt-admin.so
%{_libdir}/libvirt-qemu.so
%{_libdir}/libvirt-lxc.so
%dir %{_includedir}/libvirt
%{_includedir}/libvirt/virterror.h
%{_includedir}/libvirt/libvirt.h
%{_includedir}/libvirt/libvirt-admin.h
%{_includedir}/libvirt/libvirt-common.h
%{_includedir}/libvirt/libvirt-domain.h
%{_includedir}/libvirt/libvirt-domain-checkpoint.h
%{_includedir}/libvirt/libvirt-domain-snapshot.h
%{_includedir}/libvirt/libvirt-event.h
%{_includedir}/libvirt/libvirt-host.h
%{_includedir}/libvirt/libvirt-interface.h
%{_includedir}/libvirt/libvirt-network.h
%{_includedir}/libvirt/libvirt-nodedev.h
%{_includedir}/libvirt/libvirt-nwfilter.h
%{_includedir}/libvirt/libvirt-secret.h
%{_includedir}/libvirt/libvirt-storage.h
%{_includedir}/libvirt/libvirt-stream.h
%{_includedir}/libvirt/libvirt-qemu.h
%{_includedir}/libvirt/libvirt-lxc.h
%{_libdir}/pkgconfig/libvirt.pc
%{_libdir}/pkgconfig/libvirt-admin.pc
%{_libdir}/pkgconfig/libvirt-qemu.pc
%{_libdir}/pkgconfig/libvirt-lxc.pc

%dir %{_datadir}/libvirt/api/
%{_datadir}/libvirt/api/libvirt-api.xml
%{_datadir}/libvirt/api/libvirt-admin-api.xml
%{_datadir}/libvirt/api/libvirt-qemu-api.xml
%{_datadir}/libvirt/api/libvirt-lxc-api.xml


%changelog
* Fri Oct  9 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-29
- qemu: substitute missing model name for host-passthrough (rhbz#1850680)
- rpc: gendispatch: handle empty flags (CVE-2020-25637)
- rpc: add support for filtering @acls by uint params (CVE-2020-25637)
- rpc: require write acl for guest agent in virDomainInterfaceAddresses (CVE-2020-25637)
- qemu: agent: set ifname to NULL after freeing (CVE-2020-25637)
- qemu: Fix domfsinfo for non-PCI device information from guest agent (rhbz#1858771)
- virDomainNetFindIdx: add support for CCW addresses (rhbz#1837495)
- check for NULL before calling g_regex_unref (rhbz#1861176)
- virhostcpu.c: fix 'die_id' parsing for Power hosts (rhbz#1876742)
- qemuFirmwareFillDomain: Fill NVRAM template on migration too (rhbz#1880418)
- node_device: refactor udevProcessCCW (rhbz#1853289, rhbz#1865932)
- node_device: detect CSS devices (rhbz#1853289, rhbz#1865932)
- virsh: nodedev: ability to filter CSS capabilities (rhbz#1853289, rhbz#1865932)
- node_device: detect DASD devices (rhbz#1853289, rhbz#1865932)
- udevProcessCSS: Check if def->driver is non-NULL (rhbz#1853289, rhbz#1865932)

* Wed Aug 26 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-28
- virdevmapper: Don't cache device-mapper major (rhbz#1860421)
- virdevmapper: Handle kernel without device-mapper support (rhbz#1860421)
- virdevmapper: Ignore all errors when opening /dev/mapper/control (rhbz#1860421)

* Fri Aug  7 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-27
- src: assume sys/sysmacros.h always exists on Linux (rhbz#1860421)
- virdevmapper.c: Join two WITH_DEVMAPPER sections together (rhbz#1860421)
- virDevMapperGetTargetsImpl: Use VIR_AUTOSTRINGLIST (rhbz#1860421)
- virdevmapper: Don't use libdevmapper to obtain dependencies (CVE-2020-14339, rhbz#1860421)
- virDevMapperGetTargets: Don't ignore EBADF (rhbz#1860421)

* Fri Jul 24 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-26
- qemu: blockjob: Don't base bitmap handling of active-layer block commit on QEMU_CAPS_BLOCKDEV_REOPEN (rhbz#1857779)
- qemu: blockjob: Actually delete temporary bitmap on failed active commit (rhbz#1857779)
- qemu: block: Remove 'active-write' bitmap even if there are no bitmaps to merge (rhbz#1857779)
- qemuDomainBlockPivot: Rename 'actions' to 'bitmapactions' (rhbz#1857779)
- qemuDomainBlockPivot: Ignore failures of creating active layer bitmap (rhbz#1857779)

* Wed Jun 24 2020 Jiri Denemark <jdenemar@redhat.com> - 6.0.0-25
- Upgrade components in virt:rhel module:stream for RHEL-8.3 release (rhbz#1828317)
- conf: Don't format http cookies unless VIR_DOMAIN_DEF_FORMAT_SECURE is used (CVE-2020-14301)
- util: Introduce a parser for kernel cmdline arguments (rhbz#1848997)
- qemu: Check if s390 secure guest support is enabled (rhbz#1848997)
- qemu: Check if AMD secure guest support is enabled (rhbz#1848997)
- tools: Secure guest check on s390 in virt-host-validate (rhbz#1848997)
- tools: Secure guest check for AMD in virt-host-validate (rhbz#1848997)
- docs: Update AMD launch secure description (rhbz#1848997)
- docs: Describe protected virtualization guest setup (rhbz#1848997)

* Fri Jun 19 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1828317
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Tue Jun 09 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Fri Jun 05 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
(Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Mon Apr 27 2020 Danilo C. L. de Paula <ddepaula@redhat.com> - 6.0.0
- Resolves: bz#1810193
  (Upgrade components in virt:rhel module:stream for RHEL-8.3 release)

* Mon Mar 16 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-42
- RHEL: virscsi: Check device type before getting it's /dev node name (rhbz#1808388)
- RHEL: virscsi: Support TAPEs in virSCSIDeviceGetDevName() (rhbz#1808388)
- RHEL: virscsi: Introduce and use virSCSIDeviceGetUnprivSGIOSysfsPath() (rhbz#1808388)
- RHEL: virutil: Accept non-block devices in virGetDeviceID() (rhbz#1808388)
- RHEL: qemuSetUnprivSGIO: Actually use calculated @sysfs_path to set unpriv_sgio (rhbz#1808388)
- RHEL: qemuCheckUnprivSGIO: use @sysfs_path to get unpriv_sgio (rhbz#1808399)

* Wed Mar  4 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-41
- qemu: Translate features in virQEMUCapsGetCPUFeatures (rhbz#1804224)

* Mon Feb 17 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-40
- process: wait longer on kill per assigned Hostdev (rhbz#1785338)
- process: wait longer 5->30s on hard shutdown (rhbz#1785338)

* Mon Feb 10 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-39
- selinux: Do not report an error when not returning -1 (rhbz#1788096)
- qemu: Fix hyperv features with QEMU 4.1 (rhbz#1794868)
- qemu: Prefer dashes for hyperv features (rhbz#1794868)
- cpu: Drop KVM_ from hyperv feature macros (rhbz#1794868)
- cpu: Drop unused KVM features (rhbz#1794868)
- qemu: Fix KVM features with QEMU 4.1 (rhbz#1794868)
- cpu: Drop CPUID definition for hv-spinlocks (rhbz#1794868)

* Tue Jan 14 2020 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-38
- cpu_map/x86: Add support for BFLOAT16 data type (rhbz#1749516)

* Fri Dec 13 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-37
- cpu_map: Add TAA_NO bit for IA32_ARCH_CAPABILITIES MSR (CVE-2019-11135)
- cpu_map: Add TSX_CTRL bit for IA32_ARCH_CAPABILITIES MSR (CVE-2019-11135)

* Thu Nov 21 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-36
- cpu_conf: Pass policy to CPU feature filtering callbacks (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemuxml2*test: Add tests for Icelake-Server, -pconfig (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemu: Drop disabled CPU features unknown to QEMU (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- cputest: Add data for Ice Lake Server CPU (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- cpu_map: Drop pconfig from Icelake-Server CPU model (rhbz#1749672, rhbz#1756156, rhbz#1721608)
- qemu: Fix NULL ptr dereference caused by qemuDomainDefFormatBufInternal (rhbz#1749672, rhbz#1756156, rhbz#1721608)

* Mon Sep 16 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-35
- vircgroupv2: fix setting cpu.max period (rhbz#1749227)

* Wed Sep  4 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-34
- vircgroupv2: fix abort in VIR_AUTOFREE (rhbz#1747440)

* Mon Aug 26 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-33
- vircgroupv2: fix parsing multiple values in single file (rhbz#1741825)
- vircgroupv2: fix virCgroupV2GetCpuCfsQuota for "max" value (rhbz#1741837)

* Mon Aug 19 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-32
- virDomainObjListAddLocked: Produce better error message than 'Duplicate key' (rhbz#1737790)
- virdbus: Grab a ref as long as the while loop is executed (rhbz#1741900)

* Tue Jul 30 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-31
- virDomainObjListAddLocked: fix double free (rhbz#1728530)
- docs: schemas: Decouple the virtio options from each other (rhbz#1729675)
- util: command: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1721434)
- util: command: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1721434)
- util: netdevopenvswitch: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1721434)
- util: virnetdevopenvswitch: Drop an unused variable @ovs_timeout (rhbz#1721434)
- util: netdevopenvswitch: use VIR_AUTOPTR for aggregate types (rhbz#1721434)
- util: suppress unimportant ovs-vsctl errors when getting interface stats (rhbz#1721434)
- virNetDevOpenvswitchInterfaceStats: Optimize for speed (rhbz#1721434)
- test: Introduce virnetdevopenvswitchtest (rhbz#1721434)
- vircommand: Separate mass FD closing into a function (rhbz#1721434)
- virCommand: use procfs to learn opened FDs (rhbz#1721434)
- util: command: Ignore bitmap errors when enumerating file descriptors to close (rhbz#1721434)
- util: Avoid possible error in virCommandMassClose (rhbz#1721434)
- vircgroup: fix cgroups v2 controllers detection (rhbz#1689297)
- vircgroupv2: store enabled controllers (rhbz#1689297)

* Wed Jul  3 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-30
- virWaitForDevices: Drop confusing part of comment (rhbz#1710575)
- lib: Drop UDEVSETTLE (rhbz#1710575)
- m4: Provide default value fore UDEVADM (rhbz#1710575)
- m4: Drop needless string checks (rhbz#1710575)
- util: vircgroup: introduce virCgroup(Get|Set)ValueRaw (rhbz#1658890)
- util: vircgroup: move virCgroupGetValueStr out of virCgroupGetValueForBlkDev (rhbz#1658890)
- util: vircgroupv1: add support for BFQ blkio files (rhbz#1658890)
- util: vircgroupv2: add support for BFQ files (rhbz#1658890)
- Handle copying bitmaps to larger data buffers (rhbz#1703160)

* Tue Jul  2 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-29
- cpu: allow include files for CPU definition (rhbz#1686895)
- cpu: fix cleanup when signature parsing fails (rhbz#1686895)
- cpu: push more parsing logic into common code (rhbz#1686895)
- cpu: simplify failure cleanup paths (rhbz#1686895)
- cpu_map: Add support for arch-capabilities feature (rhbz#1693433)
- cputest: Add data for Intel(R) Xeon(R) CPU E5-2630 v4 (rhbz#1686895)
- cputest: Add data for Intel(R) Core(TM) i7-7600U (rhbz#1686895)
- cputest: Add data for Intel(R) Xeon(R) CPU E7540 (rhbz#1686895)
- cputest: Add data for Intel(R) Xeon(R) CPU E5-2650 (rhbz#1686895)
- cputest: Add data for Intel(R) Core(TM) i7-8700 (rhbz#1686895)
- cpu_x86: Separate ancestor model parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate signature parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate vendor parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Separate feature list parsing from x86ModelParse (rhbz#1686895)
- cpu_x86: Make sure CPU model names are unique in cpu_map (rhbz#1686895)
- cpu_x86: Add x86ModelCopySignatures helper (rhbz#1686895)
- cpu_x86: Store CPU signature in an array (rhbz#1686895)
- cpu_x86: Allow multiple signatures for a CPU model (rhbz#1686895)
- cpu_x86: Log decoded CPU model and signatures (rhbz#1686895)
- qemu_capabilities: Inroduce virQEMUCapsGetCPUModelX86Data (rhbz#1686895)
- qemu_capabilities: Introduce virQEMUCapsGetCPUModelInfo (rhbz#1686895)
- qemu_capabilities: Use virQEMUCapsGetCPUModelInfo (rhbz#1686895)
- cpu_x86: Add virCPUx86DataGetSignature for tests (rhbz#1686895)
- cpu_map: Add hex representation of signatures (rhbz#1686895)
- cputest: Test CPU signatures (rhbz#1686895)
- cpu_map: Add more signatures for Conroe CPU model (rhbz#1686895)
- cpu_map: Add more signatures for Penryn CPU model (rhbz#1686895)
- cpu_map: Add more signatures for Nehalem CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Westmere CPU model (rhbz#1686895)
- cpu_map: Add more signatures for SandyBridge CPU models (rhbz#1686895)
- cpu_map: Add more signatures for IvyBridge CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Haswell CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Broadwell CPU models (rhbz#1686895)
- cpu_map: Add more signatures for Skylake-Client CPU models (rhbz#1686895)
- cpu: Don't access invalid memory in virCPUx86Translate (rhbz#1686895)
- cpu_x86: Require <cpuid> within <feature> in CPU map (rhbz#1697627)
- cputest: Add data for Intel(R) Xeon(R) Platinum 8268 CPU (rhbz#1693433)
- cpu_map: Add Cascadelake-Server CPU model (rhbz#1693433)
- cpu_x86: Introduce virCPUx86DataItem container struct (rhbz#1697627)
- cpu_x86: Rename virCPUx86Vendor.cpuid (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataItem variables (rhbz#1697627)
- cpu_x86: Rename x86DataCpuidNext function (rhbz#1697627)
- cpu_x86: Rename x86DataCpuid (rhbz#1697627)
- cpu_x86: Rename virCPUx86CPUIDSorter (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataAddCPUIDInt (rhbz#1697627)
- cpu_x86: Rename virCPUx86DataAddCPUID (rhbz#1697627)
- cpu_x86: Rename virCPUx86VendorToCPUID (rhbz#1697627)
- cpu_x86: Simplify x86DataAdd (rhbz#1697627)
- cpu_x86: Introduce virCPUx86DataCmp (rhbz#1697627)
- cpu_x86: Make x86cpuidSetBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidClearBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidAndBits more general (rhbz#1697627)
- cpu_x86: Make x86cpuidMatchMasked more general (rhbz#1697627)
- cpu_x86: Make x86cpuidMatch more general (rhbz#1697627)
- cpu_x86: Store virCPUx86DataItem content in union (rhbz#1697627)
- cpu_x86: Add support for storing MSR features in CPU map (rhbz#1697627)
- cpu_x86: Move *CheckFeature functions (rhbz#1697627)
- cputest: Add support for MSR features to cpu-parse.sh (rhbz#1697627)
- util: file: introduce VIR_AUTOCLOSE macro to close fd of the file automatically (rhbz#1697627)
- vircpuhost: Add support for reading MSRs (rhbz#1697627)
- virhostcpu: Make virHostCPUGetMSR() work only on x86 (rhbz#1697627)
- cpu_x86: Fix placement of *CheckFeature functions (rhbz#1697627)
- cpu_conf: Introduce virCPUDefFilterFeatures (rhbz#1697627)
- qemu_command: Use consistent syntax for CPU features (rhbz#1697627)
- tests: Add QEMU caps data for future 4.1.0 (rhbz#1697627)
- tests: Add domain capabilities case for QEMU 4.1.0 (rhbz#1697627)
- qemuxml2argvtest: Add test for CPU features translation (rhbz#1697627)
- qemu: Add APIs for translating CPU features (rhbz#1697627)
- qemu: Probe for max-x86_64-cpu type (rhbz#1697627)
- qemu: Probe for "unavailable-features" CPU property (rhbz#1697627)
- qemu: Probe host CPU after capabilities (rhbz#1697627)
- qemu_command: Use canonical names of CPU features (rhbz#1697627)
- qemu: Translate feature names from query-cpu-model-expansion (rhbz#1697627)
- qemu: Don't use full CPU model expansion (rhbz#1697627)
- qemu: Make qemuMonitorGetGuestCPU usable on x86 only (rhbz#1697627)
- cpu: Introduce virCPUDataAddFeature (rhbz#1697627)
- qemu: Add type filter to qemuMonitorJSONParsePropsList (rhbz#1697627)
- util: string: Introduce macro for automatic string lists (rhbz#1697627)
- util: json: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1697627)
- qemu: Introduce generic qemuMonitorGetGuestCPU (rhbz#1697627)
- qemu_process: Prefer generic qemuMonitorGetGuestCPU (rhbz#1697627)
- util: Rework virStringListAdd (rhbz#1697627)
- conf: Introduce virCPUDefCheckFeatures (rhbz#1697627)
- cpu_x86: Turn virCPUx86DataIteratorInit into a function (rhbz#1697627)
- cpu_x86: Introduce virCPUx86FeatureFilter*MSR (rhbz#1697627)
- cpu_x86: Read CPU features from IA32_ARCH_CAPABILITIES MSR (rhbz#1697627)
- cpu_map: Introduce IA32_ARCH_CAPABILITIES MSR features (rhbz#1697627)
- qemu: Forbid MSR features with old QEMU (rhbz#1697627)
- qemu: Drop MSR features from host-model with old QEMU (rhbz#1697627)
- cpu_x86: Fix memory leak - virCPUx86GetHost (rhbz#1697627)
- qemu: Use @tmpChr in qemuDomainDetachChrDevice to build device string (rhbz#1624204)
- qemu: Drop "user-" prefix for guestfwd netdev (rhbz#1624204)
- qemu_hotplug: Attach guestfwd using netdev_add (rhbz#1624204)
- qemu_hotplug: Detach guestfwd using netdev_del (rhbz#1624204)
- qemuhotplugtest: Test guestfwd attach and detach (rhbz#1624204)
- daemon: Register secret driver before storage driver (rhbz#1685151)
- bhyve: Move autostarting of domains into bhyveStateInitialize (rhbz#1685151)
- Revert "virStateDriver - Separate AutoStart from Initialize" (rhbz#1685151)
- Revert "Separate out StateAutoStart from StateInitialize" (rhbz#1685151)
- util: moving 'type' argument to avoid issues with mount() syscall. (rhbz#1689297)
- util: cgroup: use VIR_AUTOFREE instead of VIR_FREE for scalar types (rhbz#1689297)
- vircgroup: Rename structs to start with underscore (rhbz#1689297)
- vircgroup: Introduce standard set of typedefs and use them (rhbz#1689297)
- vircgroup: Extract file link resolving into separate function (rhbz#1689297)
- vircgroup: Remove unused function virCgroupKill() (rhbz#1689297)
- vircgroup: Unexport unused function virCgroupAddTaskController() (rhbz#1689297)
- vircgroup: Unexport unused function virCgroupRemoveRecursively (rhbz#1689297)
- vircgroup: Move function used in tests into vircgrouppriv.h (rhbz#1689297)
- vircgroup: Remove pointless bool parameter (rhbz#1689297)
- vircgroup: Extract mount options matching into function (rhbz#1689297)
- vircgroup: Use virCgroupMountOptsMatchController in virCgroupDetectPlacement (rhbz#1689297)
- vircgroup: Introduce virCgroupEnableMissingControllers (rhbz#1689297)
- vircgroup: machinename will never be NULL (rhbz#1689297)
- vircgroup: Remove virCgroupAddTaskController (rhbz#1689297)
- vircgroup: Introduce virCgroupGetMemoryStat (rhbz#1689297)
- lxc: Use virCgroupGetMemoryStat (rhbz#1689297)
- vircgroup: fix MinGW build (rhbz#1689297)
- vircgroup: Duplicate string before modifying (rhbz#1689297)
- vircgroup: Extract controller detection into function (rhbz#1689297)
- vircgroup: Extract placement validation into function (rhbz#1689297)
- vircgroup: Split virCgroupPathOfController into two functions (rhbz#1689297)
- vircgroup: Call virCgroupRemove inside virCgroupMakeGroup (rhbz#1689297)
- vircgroup: Simplify if conditions in virCgroupMakeGroup (rhbz#1689297)
- vircgroup: Remove obsolete sa_assert (rhbz#1689297)
- tests: Resolve possible overrun (rhbz#1689297)
- vircgroup: cleanup controllers not managed by systemd on error (rhbz#1689297)
- vircgroup: fix bug in virCgroupEnableMissingControllers (rhbz#1689297)
- vircgroup: rename virCgroupAdd.*Task to virCgroupAdd.*Process (rhbz#1689297)
- vircgroup: introduce virCgroupTaskFlags (rhbz#1689297)
- vircgroup: introduce virCgroupAddThread (rhbz#1689297)
- vircgroupmock: cleanup unused cgroup files (rhbz#1689297)
- vircgroupmock: rewrite cgroup fopen mocking (rhbz#1689297)
- vircgrouptest: call virCgroupDetectMounts directly (rhbz#1689297)
- vircgrouptest: call virCgroupNewSelf instead virCgroupDetectMounts (rhbz#1689297)
- util: introduce vircgroupbackend files (rhbz#1689297)
- vircgroup: introduce cgroup v1 backend files (rhbz#1689297)
- vircgroup: extract virCgroupV1Available (rhbz#1689297)
- vircgroup: detect available backend for cgroup (rhbz#1689297)
- vircgroup: extract virCgroupV1ValidateMachineGroup (rhbz#1689297)
- vircgroup: extract virCgroupV1CopyMounts (rhbz#1689297)
- vircgroup: extract v1 detect functions (rhbz#1689297)
- vircgroup: extract virCgroupV1CopyPlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1ValidatePlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1StealPlacement (rhbz#1689297)
- vircgroup: extract virCgroupV1DetectControllers (rhbz#1689297)
- vircgroup: extract virCgroupV1HasController (rhbz#1689297)
- vircgroup: extract virCgroupV1GetAnyController (rhbz#1689297)
- vircgroup: extract virCgroupV1PathOfController (rhbz#1689297)
- vircgroup: extract virCgroupV1MakeGroup (rhbz#1689297)
- vircgroup: extract virCgroupV1Remove (rhbz#1689297)
- vircgroup: extract virCgroupV1AddTask (rhbz#1689297)
- vircgroup: extract virCgroupV1HasEmptyTasks (rhbz#1689297)
- vircgroup: extract virCgroupV1BindMount (rhbz#1689297)
- vircgroup: extract virCgroupV1SetOwner (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioWeight (rhbz#1689297)
- vircgroup: extract virCgroupV1GetBlkioIoServiced (rhbz#1689297)
- vircgroup: extract virCgroupV1GetBlkioIoDeviceServiced (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWeight (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceReadIops (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWriteIops (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceReadBps (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)BlkioDeviceWriteBps (rhbz#1689297)
- vircgroup: extract virCgroupV1SetMemory (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemoryStat (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemoryUsage (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)Memory*Limit (rhbz#1689297)
- vircgroup: extract virCgroupV1GetMemSwapUsage (rhbz#1689297)
- vircgroup: extract virCgroupV1(Allow|Deny)Device (rhbz#1689297)
- vircgroup: extract virCgroupV1(Allow|Deny)AllDevices (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuShares (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuCfsPeriod (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpuCfsQuota (rhbz#1689297)
- vircgroup: extract virCgroupV1SupportsCpuBW (rhbz#1689297)
- vircgroup: extract virCgroupV1GetCpuacct*Usage (rhbz#1689297)
- vircgroup: extract virCgroupV1GetCpuacctStat (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)FreezerState (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetMems (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetMemoryMigrate (rhbz#1689297)
- vircgroup: extract virCgroupV1(Set|Get)CpusetCpus (rhbz#1689297)
- vircgroup: rename virCgroupController into virCgroupV1Controller (rhbz#1689297)
- vircgroup: rename controllers to legacy (rhbz#1689297)
- vircgroup: remove VIR_CGROUP_SUPPORTED (rhbz#1689297)
- vircgroup: include system headers only on linux (rhbz#1689297)
- vircgroupv1: fix build on non-linux OSes (rhbz#1689297)
- Revert "vircgroup: cleanup controllers not managed by systemd on error" (rhbz#1689297)
- util: introduce cgroup v2 files (rhbz#1689297)
- vircgroup: introduce virCgroupV2Available (rhbz#1689297)
- vircgroup: introduce virCgroupV2ValidateMachineGroup (rhbz#1689297)
- vircgroup: introduce virCgroupV2CopyMounts (rhbz#1689297)
- vircgroup: introduce virCgroupV2CopyPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectMounts (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2ValidatePlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2StealPlacement (rhbz#1689297)
- vircgroup: introduce virCgroupV2DetectControllers (rhbz#1689297)
- vircgroup: introduce virCgroupV2HasController (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetAnyController (rhbz#1689297)
- vircgroup: introduce virCgroupV2PathOfController (rhbz#1689297)
- vircgroup: introduce virCgroupV2MakeGroup (rhbz#1689297)
- vircgroup: introduce virCgroupV2Remove (rhbz#1689297)
- vircgroup: introduce virCgroupV2AddTask (rhbz#1689297)
- vircgroup: introduce virCgroupV2HasEmptyTasks (rhbz#1689297)
- vircgroup: introduce virCgroupV2BindMount (rhbz#1689297)
- vircgroup: introduce virCgroupV2SetOwner (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioWeight (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetBlkioIoServiced (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetBlkioIoDeviceServiced (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWeight (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceReadIops (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWriteIops (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceReadBps (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)BlkioDeviceWriteBps (rhbz#1689297)
- vircgroup: introduce virCgroupV2SetMemory (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemoryStat (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemoryUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemoryHardLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemorySoftLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)MemSwapHardLimit (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetMemSwapUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuShares (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuCfsPeriod (rhbz#1689297)
- vircgroup: introduce virCgroupV2(Set|Get)CpuCfsQuota (rhbz#1689297)
- vircgroup: introduce virCgroupV2SupportsCpuBW (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetCpuacctUsage (rhbz#1689297)
- vircgroup: introduce virCgroupV2GetCpuacctStat (rhbz#1689297)
- vircgroup: register cgroup v2 backend (rhbz#1689297)
- vircgroup: add support for hybrid configuration (rhbz#1689297)
- vircgroupmock: change cgroup prefix (rhbz#1689297)
- vircgroupmock: add support to test cgroup v2 (rhbz#1689297)
- vircgrouptest: introduce initFakeFS and cleanupFakeFS helpers (rhbz#1689297)
- vircgrouptest: prepare testCgroupDetectMounts for cgroup v2 (rhbz#1689297)
- vircgrouptest: add detect mounts test for cgroup v2 (rhbz#1689297)
- vircgrouptest: add detect mounts test for hybrid cgroups (rhbz#1689297)
- vircgrouptest: prepare validateCgroup for cgroupv2 (rhbz#1689297)
- vircgrouptest: add cgroup v2 tests (rhbz#1689297)
- vircgrouptest: add hybrid tests (rhbz#1689297)
- virt-host-validate: rewrite cgroup detection to use util/vircgroup (rhbz#1689297)
- virt-host-validate: require freezer for LXC (rhbz#1689297)
- virt-host-validate: Fix build on non-Linux (rhbz#1689297)
- tests: Use correct function name in error path (rhbz#1689297)
- util: Fix virCgroupGetMemoryStat (rhbz#1689297)
- tests: Augment vcgrouptest to add virCgroupGetMemoryStat (rhbz#1689297)
- vircgroup: introduce virCgroupKillRecursiveCB (rhbz#1689297)
- vircgroupv2: fix virCgroupV2ValidateMachineGroup (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetMems (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetMemoryMigrate (rhbz#1689297)
- util: implement virCgroupV2(Set|Get)CpusetCpus (rhbz#1689297)
- util: enable cgroups v2 cpuset controller for threads (rhbz#1689297)
- util: vircgroup: pass parent cgroup into virCgroupDetectControllersCB (rhbz#1689297)
- internal: introduce a family of NULLSTR macros (rhbz#1689297)
- util: vircgroup: improve controller detection (rhbz#1689297)
- util: vircgroupv2: use any controller to create thread directory (rhbz#1689297)
- util: vircgroupv2: enable CPU controller only if it's available (rhbz#1689297)
- util: vircgroupv2: separate return values of virCgroupV2EnableController (rhbz#1689297)
- util: vircgroupv2: don't error out if enabling controller fails (rhbz#1689297)
- util: vircgroupv2: mark only requested controllers as available (rhbz#1689297)
- Revert "util: vircgroup: pass parent cgroup into virCgroupDetectControllersCB" (rhbz#1689297)
- util: vircgroupv2: stop enabling missing controllers with systemd (rhbz#1689297)

* Fri Jun 28 2019 Danilo de Paula <ddepaula@redhat.com> - 4.5.0-28
- Rebuild all virt packages to fix RHEL's upgrade path
- Resolves: rhbz#1695587
  (Ensure modular RPM upgrade path)

* Fri Jun 21 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-27
- RHEL: spec: Disable gluster on i686 (rhbz#1722668)
- rpc: virnetlibsshsession: update deprecated functions (rhbz#1722735)

* Thu Jun 20 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-26
- api: disallow virDomainSaveImageGetXMLDesc on read-only connections (CVE-2019-10161)
- api: disallow virDomainManagedSaveDefineXML on read-only connections (CVE-2019-10166)
- api: disallow virConnectGetDomainCapabilities on read-only connections (CVE-2019-10167)
- api: disallow virConnect*HypervisorCPU on read-only connections (CVE-2019-10168)

* Fri Jun 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-25
- admin: reject clients unless their UID matches the current UID (CVE-2019-10132)
- locking: restrict sockets to mode 0600 (CVE-2019-10132)
- logging: restrict sockets to mode 0600 (CVE-2019-10132)
- util: skip RDMA detection for non-PCI network devices (rhbz#1693299)
- virfile: Detect ceph as shared FS (rhbz#1698133)
- virfile: added GPFS as shared fs (rhbz#1698133)
- util: bitmap: define cleanup function using VIR_DEFINE_AUTOPTR_FUNC (rhbz#1716943)
- qemu: Rework setting process affinity (rhbz#1716943)
- qemu: Set up EMULATOR thread and cpuset.mems before exec()-ing qemu (rhbz#1716943)
- conf: Add definitions for 'uid' and 'fid' PCI address attributes (rhbz#1508149)
- qemu: Introduce zPCI capability (rhbz#1508149)
- qemu: Enable PCI multi bus for S390 guests (rhbz#1508149)
- conf: Introduce extension flag and zPCI member for PCI address (rhbz#1508149)
- conf: Introduce address caching for PCI extensions (rhbz#1508149)
- qemu: Auto add pci-root for s390/s390x guests (rhbz#1508149)
- conf: use virXMLFormatElement() in virDomainDeviceInfoFormat() (rhbz#1508149)
- conf: Introduce parser, formatter for uid and fid (rhbz#1508149)
- qemu: Add zPCI address definition check (rhbz#1508149)
- conf: Allocate/release 'uid' and 'fid' in PCI address (rhbz#1508149)
- qemu: Generate and use zPCI device in QEMU command line (rhbz#1508149)
- qemu: Add hotpluging support for PCI devices on S390 guests (rhbz#1508149)
- qemuDomainRemoveRNGDevice: Remove associated chardev too (rhbz#1508149)
- qemu_hotplug: remove erroneous call to qemuDomainDetachExtensionDevice() (rhbz#1508149)
- qemu_hotplug: remove another erroneous qemuDomainDetachExtensionDevice() call (rhbz#1508149)
- util: Propagate numad failures correctly (rhbz#1716907)
- util: Introduce virBitmapUnion() (rhbz#1716908)
- util: Introduce virNumaNodesetToCPUset() (rhbz#1716908)
- qemu: Fix qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Fix leak in qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Drop cleanup label from qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemu: Fix NULL pointer access in qemuProcessInitCpuAffinity() (rhbz#1716908)
- qemuBuildMemoryBackendProps: Pass @priv instead of its individual members (rhbz#1624223)
- qemu: Don't use -mem-prealloc among with .prealloc=yes (rhbz#1624223)
- nwfilter: fix adding std MAC and IP values to filter binding (rhbz#1691356)
- qemuProcessBuildDestroyMemoryPathsImpl: Don't overwrite error (rhbz#1658112)
- qemu_security: Fully implement qemuSecurityDomainSetPathLabel (rhbz#1658112)
- qemu: process: SEV: Assume libDir to be the directory to create files in (rhbz#1658112)
- qemu: process: SEV: Relabel guest owner's SEV files created before start (rhbz#1658112)

* Tue May 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-24
- tests: qemuxml2argv: add CAPS_ARCH_LATEST macro (rhbz#1698855)
- qemu: Add ccw support for vhost-vsock (rhbz#1698855)
- qemu: Allow creating ppc64 guests with graphics and no USB mouse (rhbz#1683681)
- conf: Expose virDomainSCSIDriveAddressIsUsed (rhbz#1692354)
- qemuhotplugtest: Don't plug a SCSI disk at unit 7 (rhbz#1692354)
- qemu_hotplug: Check for duplicate drive addresses (rhbz#1692354)
- cpu_map: Add support for cldemote CPU feature (rhbz#1537731)
- util: alloc: add macros for implementing automatic cleanup functionality (rhbz#1505998)
- qemu: domain: Simplify non-VFIO memLockLimit calculation for PPC64 (rhbz#1505998)
- qemu_domain: add a PPC64 memLockLimit helper (rhbz#1505998)
- qemu_domain: NVLink2 bridge detection function for PPC64 (rhbz#1505998)
- PPC64 support for NVIDIA V100 GPU with NVLink2 passthrough (rhbz#1505998)
- cpu_x86: Do not cache microcode version (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- qemu: Don't cache microcode version (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- cputest: Add data for Intel(R) Xeon(R) CPU E3-1225 v5 (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)
- cpu_map: Define md-clear CPUID bit (CVE-2018-12127, CVE-2019-11091, CVE-2018-12126, CVE-2018-12130)

* Fri Feb 15 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-23
- network: explicitly allow icmp/icmpv6 in libvirt zonefile (rhbz#1650320)

* Fri Feb 15 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-22
- util: fix memory leak in virFirewallDInterfaceSetZone() (rhbz#1650320)

* Fri Feb  8 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-21
- docs: Drop /dev/net/tun from the list of shared devices (rhbz#1665400)
- qemu: conf: Remove /dev/sev from the default cgroup device acl list (rhbz#1665400)
- qemu: cgroup: Expose /dev/sev/ only to domains that require SEV (rhbz#1665400)
- qemu: domain: Add /dev/sev into the domain mount namespace selectively (rhbz#1665400)
- security: dac: Relabel /dev/sev in the namespace (rhbz#1665400)
- qemu: caps: Use CAP_DAC_OVERRIDE for probing to avoid permission issues (rhbz#1665400)
- qemu: caps: Don't try to ask for CAP_DAC_OVERRIDE if non-root (rhbz#1665400)
- Revert "RHEL: Require firewalld-filesystem for firewalld rpm macros" (rhbz#1650320)
- Revert "RHEL: network: regain guest network connectivity after firewalld switch to nftables" (rhbz#1650320)
- configure: change HAVE_FIREWALLD to WITH_FIREWALLD (rhbz#1650320)
- util: move all firewalld-specific stuff into its own files (rhbz#1650320)
- util: new virFirewallD APIs + docs (rhbz#1650320)
- configure: selectively install a firewalld 'libvirt' zone (rhbz#1650320)
- network: set firewalld zone of bridges to "libvirt" zone when appropriate (rhbz#1650320)
- network: allow configuring firewalld zone for virtual network bridge device (rhbz#1650320)
- util: remove test code accidentally committed to virFirewallDZoneExists (rhbz#1650320)
- qemu: command: Don't skip 'readonly' and throttling info for empty drive (rhbz#1670337)

* Mon Jan 28 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-20
- RHEL: qemu: Fix crash trying to use iSCSI hostdev (rhbz#1669424)

* Thu Jan 24 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-19
- qemu: Fix logic error in qemuSetUnprivSGIO (rhbz#1666605)
- tests: qemuxml2argv: Add test case for empty CDROM with cache mode (rhbz#1553255)
- qemu: command: Don't format image properties for empty -drive (rhbz#1553255)

* Mon Jan 14 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-18
- conf: correct false boot order error during domain parse (rhbz#1630393)
- qemu: Remove duplicated qemuAgentCheckError (rhbz#1665000)
- qemu: require reply from guest agent in qemuAgentGetInterfaces (rhbz#1665000)
- qemu: Filter non SCSI hostdevs in qemuHostdevPrepareSCSIDevices (rhbz#1665244)
- util: remove const specifier from nlmsghdr arg to virNetlinkDumpCallback() (rhbz#1583131)
- util: add a function to insert new interfaces to IPv6CheckForwarding list (rhbz#1583131)
- util: use nlmsg_find_attr() instead of an open-coded loop (rhbz#1583131)
- util: check accept_ra for all nexthop interfaces of multipath routes (rhbz#1583131)
- util: make forgotten changes suggested during review of commit d40b820c (rhbz#1583131)

* Mon Jan  7 2019 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-17
- virsh: Strip XML declaration when extracting CPU XMLs (rhbz#1659048)
- RHEL: qemu: Add ability to set sgio values for hostdev (rhbz#1582424)
- RHEL: qemu: Add check for unpriv sgio for SCSI generic host device (rhbz#1582424)
- qemu: Alter @val usage in qemuSetUnprivSGIO (rhbz#1656362)
- qemu: Alter qemuSetUnprivSGIO hostdev shareable logic (rhbz#1656362)

* Mon Dec 17 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-16
- util: Don't overflow in virRandomBits (rhbz#1655586)
- virrandom: Avoid undefined behaviour in virRandomBits (rhbz#1655586)
- spec: remove libcgroup and cgconfig (rhbz#1602407)
- qemu: Drop duplicated code from qemuDomainDefValidateFeatures() (rhbz#1647822)
- tests: Add capabilities data for QEMU 3.1.0 on ppc64 (rhbz#1647822)
- qemu: Introduce QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV (rhbz#1647822)
- conf: Parse and format nested-hv feature (rhbz#1647822)
- qemu: Format nested-hv feature on the command line (rhbz#1647822)
- qemu: Add check for whether KVM nesting is enabled (rhbz#1645139)
- secret: Add check/validation for correct usage when LookupByUUID (rhbz#1656255)
- cpu: Add support for "stibp" x86_64 feature (rhbz#1655032)

* Mon Dec  3 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-15
- virfile: Take symlink into account in virFileIsSharedFixFUSE (rhbz#1634782)
- qemu: Ignore nwfilter binding instantiation issues during reconnect (rhbz#1648544)
- qemu: Set identity for the reconnect all thread (rhbz#1648546)
- Revert "access: Modify the VIR_ERR_ACCESS_DENIED to include driverName" (rhbz#1631608)
- access: Modify the VIR_ERR_ACCESS_DENIED to include driverName (rhbz#1631608)
- qemu: add vfio-ap capability (rhbz#1508146)
- qemu: vfio-ap device support (rhbz#1508146)
- qemu: Extract MDEV VFIO PCI validation code into a separate helper (rhbz#1508146)
- conf: Move VFIO AP validation from post parse to QEMU validation code (rhbz#1508146)
- qemu: Fix post-copy migration on the source (rhbz#1649169)

* Fri Nov  9 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-14
- storage: Remove secretPath from _virStorageBackendQemuImgInfo (rhbz#1645459)
- storage: Allow for inputvol to have any format for encryption (rhbz#1645459)
- storage: Allow inputvol to be encrypted (rhbz#1645459)
- access: Modify the VIR_ERR_ACCESS_DENIED to include driverName (rhbz#1631608)
- docs: Enhance polkit documentation to describe secondary connection (rhbz#1631608)
- qemu: Don't ignore resume events (rhbz#1634758, rhbz#1643338)

* Thu Nov  1 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-13
- Revert "spec: Temporarily drop gluster support" (rhbz#1599339)

* Wed Oct 17 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-12
- RHEL: Require firewalld-filesystem for firewalld rpm macros (rhbz#1639932)

* Tue Oct 16 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-11
- virfile: fix cast-align error (rhbz#1634782)
- virfiletest: Fix test name prefix for virFileInData test (rhbz#1634782)
- virfiletst: Test virFileIsSharedFS (rhbz#1634782)
- virFileIsSharedFSType: Detect direct mount points (rhbz#1634782)
- virfile: Rework virFileIsSharedFixFUSE (rhbz#1634782)
- RHEL: network: regain guest network connectivity after firewalld switch to nftables (rhbz#1638864)

* Mon Oct  8 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-10
- conf: Fix check for chardev source path (rhbz#1609723)
- tests: Reuse qemucapabilities data for qemucaps2xml (rhbz#1629862)
- tests: Add more tests to qemucaps2xml (rhbz#1629862)
- qemu: Drop QEMU_CAPS_ENABLE_KVM (rhbz#1629862)
- qemu: Avoid probing non-native binaries all the time (rhbz#1629862)
- qemu: Clarify QEMU_CAPS_KVM (rhbz#1629862)
- qemu: Don't check for /dev/kvm presence (rhbz#1629862)
- tests: Follow up on qemucaps2xmldata rename (rhbz#1629862)
- security: dac: also label listen UNIX sockets (rhbz#1634775)
- spec: Set correct TLS priority (rhbz#1632269)
- spec: Build ceph and gluster support everywhere (rhbz#1599546)
- virsh: Require explicit --domain for domxml-to-native (rhbz#1634769)
- virFileIsSharedFSType: Check for fuse.glusterfs too (rhbz#1634782)
- qemu: fix up permissions for pre-created UNIX sockets (rhbz#1634775)
- cpu_map: Add features for Icelake CPUs (rhbz#1527657, rhbz#1526625)
- cpu_map: Add Icelake CPU models (rhbz#1526625)
- qemu: Properly report VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT (rhbz#1634758)
- qemu: Report more appropriate running reasons (rhbz#1634758)
- qemu: Pass running reason to RESUME event handler (rhbz#1634758)
- qemu: Map running reason to resume event detail (rhbz#1634758)
- qemu: Avoid duplicate resume events and state changes (rhbz#1634758)
- conf: qemu: add support for Hyper-V frequency MSRs (rhbz#1589702)
- conf: qemu: add support for Hyper-V reenlightenment notifications (rhbz#1589702)
- conf: qemu: add support for Hyper-V PV TLB flush (rhbz#1589702)

* Wed Sep  5 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-9
- RHEL: Fix virConnectGetMaxVcpus output (rhbz#1582222)
- storage: Add --shrink to qemu-img command when shrinking vol (rhbz#1622534)
- access: Fix nwfilter-binding ACL access API name generation (rhbz#1622540)
- conf: Add validation of input devices (rhbz#1591240)
- tests: qemu: Remove disk from graphics-vnc-tls (rhbz#1598167)
- tests: qemu: test more versions for graphics-vnc-tls (rhbz#1598167)
- qemu: vnc: switch to tls-creds-x509 (rhbz#1598167)
- qemu: mdev: Use vfio-pci 'display' property only with vfio-pci mdevs (rhbz#1624740)
- virDomainDefCompatibleDevice: Relax alias change check (rhbz#1603133)
- virDomainDetachDeviceFlags: Clarify update semantics (rhbz#1603133)
- virDomainNetDefCheckABIStability: Check for MTU change too (rhbz#1623158)
- RHEL: spec: Require python3-devel on RHEL-8 (rhbz#1518446)
- qemu: monitor: Remove qemuMonitorJSONExtractCPUArchInfo wrapper (rhbz#1598829)
- qemu: monitor: Use 'target' instead of 'arch' in reply of 'query-cpus-fast' (rhbz#1598829)

* Tue Aug 21 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-8
- tests: Add missing thread_siblings_list files (rhbz#1608479)
- util: Rewrite virHostCPUCountThreadSiblings() (rhbz#1608479)
- utils: Remove arbitrary limit on socket_id/core_id (rhbz#1608479)
- tests: Add linux-high-ids test (rhbz#1608479)
- qemu: hotplug: Fix asynchronous unplug of 'shmem' (rhbz#1618680)
- tests: rename hugepages to hugepages-default (rhbz#1615461)
- tests: extract hugepages-numa-default-dimm out of hugepages-numa (rhbz#1615461)
- tests: rename hugepages-numa into hugepages-numa-default (rhbz#1615461)
- tests: remove unnecessary XML elements from hugepages-numa-default (rhbz#1615461)
- tests: extract pages-discard out of hugepages-pages (rhbz#1615461)
- tests: rename hugepages-pages into hugepages-numa-nodeset (rhbz#1615461)
- tests: rename hugepages-pages2 into hugepages-numa-default-2M (rhbz#1615461)
- tests: extract pages-discard-hugepages out of hugepages-pages3 (rhbz#1615461)
- tests: rename hugepages-pages3 into hugepages-numa-nodeset-part (rhbz#1615461)
- tests: rename hugepages-pages4 into hugepages-numa-nodeset-nonexist (rhbz#1615461)
- tests: rename hugepages-pages5 into hugepages-default-2M (rhbz#1615461)
- tests: rename hugepages-pages6 into hugepages-default-system-size (rhbz#1615461)
- tests: rename hugepages-pages7 into pages-dimm-discard (rhbz#1615461)
- tests: rename hugepages-pages8 into hugepages-nodeset-nonexist (rhbz#1615461)
- tests: introduce hugepages-default-1G-nodeset-2M (rhbz#1615461)
- tests: introduce hugepages-nodeset (rhbz#1615461)
- conf: Move hugepage XML validation check out of qemu_command (rhbz#1615461)
- conf: Move hugepages validation out of XML parser (rhbz#1615461)
- conf: Introduce virDomainDefPostParseMemtune (rhbz#1615461)
- tests: sev: Test launch-security with specific QEMU version (rhbz#1619150)
- qemu: Fix probing of AMD SEV support (rhbz#1619150)
- qemu: caps: Format SEV platform data into qemuCaps cache (rhbz#1619150)
- conf: Parse guestfwd channel device info again (rhbz#1610072)

* Thu Aug 16 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-7
- qemu_migration: Avoid writing to freed memory (rhbz#1615854)

* Thu Aug  2 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-6
- qemu: Exempt video model 'none' from getting a PCI address on Q35
- conf: Fix a error msg typo in virDomainVideoDefValidate

* Tue Jul 31 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-5
- esx storage: Fix typo lsilogic -> lsiLogic
- networkGetDHCPLeases: Don't always report error if unable to read leases file
- nwfilter: Resolve SEGV for NWFilter Snoop processing
- qemu: Remove unused bypassSecurityDriver from qemuOpenFileAs
- qemuDomainSaveMemory: Don't enforce dynamicOwnership
- domain_nwfilter: Return early if net has no name in virDomainConfNWFilterTeardownImpl
- examples: Add clean-traffic-gateway into nwfilters

* Mon Jul 23 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-4
- qemu: hotplug: don't overwrite error message in qemuDomainAttachNetDevice
- qemu: hotplug: report error when changing rom enabled attr for net iface
- qemu: Fix setting global_period cputune element
- tests: qemucaps: Add test data for upcoming qemu 3.0.0
- qemu: capabilities: Add capability for werror/rerror for 'usb-device' frontend
- qemu: command: Move graphics iteration to its own function
- qemu: address: Handle all the video devices within a single loop
- conf: Introduce virDomainVideoDefClear helper
- conf: Introduce virDomainDefPostParseVideo helper
- qemu: validate: Enforce compile time switch type checking for videos
- tests: Add capabilities data for QEMU 2.11 x86_64
- tests: Update capabilities data for QEMU 3.0.0 x86_64
- qemu: qemuBuildHostdevCommandLine: Use a helper variable mdevsrc
- qemu: caps: Introduce a capability for egl-headless
- qemu: Introduce a new graphics display type 'headless'
- qemu: caps: Add vfio-pci.display capability
- conf: Introduce virDomainGraphicsDefHasOpenGL helper
- conf: Replace 'error' with 'cleanup' in virDomainHostdevDefParseXMLSubsys
- conf: Introduce new <hostdev> attribute 'display'
- qemu: command: Enable formatting vfio-pci.display option onto cmdline
- docs: Rephrase the mediated devices hostdev section a bit
- conf: Introduce new video type 'none'
- virt-xml-validate: Add schema for nwfilterbinding
- tools: Fix typo generating adapter_wwpn field
- src: Fix memory leak in virNWFilterBindingDispose

* Mon Jul 23 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-3
- qemu: hotplug: Do not try to add secret object for TLS if it does not exist
- qemu: monitor: Make qemuMonitorAddObject more robust against programming errors
- spec: Explicitly require matching libvirt-libs
- virDomainConfNWFilterInstantiate: initialize @xml to avoid random crash
- qemuProcessStartPRDaemonHook: Try to set NS iff domain was started with one
- qemuDomainValidateStorageSource: Relax PR validation
- virStoragePRDefFormat: Suppress path formatting for migratable XML
- qemu: Wire up PR_MANAGER_STATUS_CHANGED event
- qemu_monitor: Introduce qemuMonitorJSONGetPRManagerInfo
- qemu: Fetch pr-helper process info on reconnect
- qemu: Fix ATTRIBUTE_NONNULL for qemuMonitorAddObject
- virsh.pod: Fix a command name typo in nwfilter-binding-undefine
- docs: schema: Add missing <alias> to vsock device
- virnetdevtap: Don't crash on !ifname in virNetDevTapInterfaceStats
- tests: fix TLS handshake failure with TLS 1.3

* Mon Jul  9 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-2
- qemu: Add capability for the HTM pSeries feature
- conf: Parse and format the HTM pSeries feature
- qemu: Format the HTM pSeries feature
- qemu: hotplug: Don't access srcPriv when it's not allocated
- qemuDomainNestedJobAllowed: Allow QEMU_JOB_NONE
- src: Mention DEVICE_REMOVAL_FAILED event in virDomainDetachDeviceAlias docs
- virsh.pod: Drop --persistent for detach-device-alias
- qemu: don't use chardev FD passing with standalone args
- qemu: remove chardevStdioLogd param from vhostuser code path
- qemu: consolidate parameters of qemuBuildChrChardevStr into flags
- qemu: don't use chardev FD passing for vhostuser backend
- qemu: fix UNIX socket chardevs operating in client mode
- qemuDomainDeviceDefValidateNetwork: Check for range only if IP prefix set
- spec: Temporarily drop gluster support

* Tue Jul  3 2018 Jiri Denemark <jdenemar@redhat.com> - 4.5.0-1
- Rebased to libvirt-4.5.0

* Fri May 25 2018 Jiri Denemark <jdenemar@redhat.com> - 4.3.0-1
- Rebased to libvirt-4.3.0

* Wed Mar 21 2018 Daniel P. Berrangé <berrange@redhat.com> - 4.1.0-2
- Fix systemd macro argument with line continuations (rhbz#1558648)

* Mon Mar  5 2018 Daniel Berrange <berrange@redhat.com> - 4.1.0-1
- Rebase to version 4.1.0

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Fri Jan 19 2018 Daniel P. Berrange <berrange@redhat.com> - 4.0.0-1
- Rebase to version 4.0.0

* Wed Dec 20 2017 Cole Robinson <crobinso@redhat.com> - 3.10.0-2
- Rebuild for xen 4.10

* Tue Dec  5 2017 Daniel P. Berrange <berrange@redhat.com> - 3.10.0-1
- Rebase to version 3.10.0

* Fri Nov  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.9.0-1
- Rebase to version 3.9.0

* Wed Oct  4 2017 Daniel P. Berrange <berrange@redhat.com> - 3.8.0-1
- Rebase to version 3.8.0

* Mon Sep  4 2017 Daniel P. Berrange <berrange@redhat.com> - 3.7.0-1
- Rebase to version 3.7.0

* Wed Aug  2 2017 Daniel P. Berrange <berrange@redhat.com> - 3.6.0-1
- Rebase to version 3.6.0

* Sun Jul 30 2017 Florian Weimer <fweimer@redhat.com> - 3.5.0-4
- Rebuild with binutils fix for ppc64le (#1475636)

* Tue Jul 25 2017 Daniel P. Berrange <berrange@redhat.com> - 3.5.0-3
- Disabled RBD on i386, arm, ppc64 (rhbz #1474743)

* Mon Jul 17 2017 Cole Robinson <crobinso@redhat.com> - 3.5.0-2
- Rebuild for xen 4.9

* Thu Jul  6 2017 Daniel P. Berrange <berrange@redhat.com> - 3.5.0-1
- Rebase to version 3.5.0

* Fri Jun  2 2017 Daniel P. Berrange <berrange@redhat.com> - 3.4.0-1
- Rebase to version 3.4.0

* Mon May  8 2017 Daniel P. Berrange <berrange@redhat.com> - 3.3.0-1
- Rebase to version 3.3.0

* Mon Apr  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.2.0-1
- Rebase to version 3.2.0

* Fri Mar  3 2017 Daniel P. Berrange <berrange@redhat.com> - 3.1.0-1
- Rebase to version 3.1.0

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Jan 19 2017 Daniel P. Berrange <berrange@redhat.com> - 3.0.0-1
- Rebase to version 3.0.0
