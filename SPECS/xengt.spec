%define vendor_name Intel Corporation
%define driver_name xengt

%define module_dir extra

%if %undefined kernel_version
%define kernel_version %(uname -r)
%endif
%if %undefined module_dir
%define module_dir updates
%endif
%if %undefined modules_suffix
%define modules_suffix modules
%endif

%define modules_package %{kernel_version}-%{modules_suffix}

Summary: %{vendor_name} %{driver_name}
Name: %{driver_name}
Version: 4.0.0
Release: 1
Vendor: %{vendor_name}
License: GPLv2
Group: System Environment/Kernel
Source0: https://code.citrite.net/rest/archive/latest/projects/XS/repos/xengt-4.x/archive?at=6d9230cddb6&format=tar.gz&prefix=%{name}-%{version}#/%{name}-%{version}.tar.gz
Patch0: import-intel_ips_h
Patch1: build-system-integration.patch
Patch2: 0001-wrap-all-unreview-patches.patch
Patch3: 0002-Revice-the-execlist-dump.patch
Patch4: 0003-vgt-Media-code-cleanup-for-BDW-VCS2.patch
Patch5: 0004-i915-vgt-re-enable-i915-golden-context.patch
Patch6: 0005-vgt-tools-vgt_report-change-the-default-path-of-vgt-.patch
Patch7: 0006-vgt-save-restore-BCS-ring-registers-for-BDW-during-c.patch
Patch8: 0007-revise-some-symbol-names.patch
Patch9: 0008-Remove-the-preemption-emulation.patch
Patch10: 0009-Reset-execlist-related-internal-structure-after-s3.patch
Patch11: 0010-vgt-handle-uninitialized-context-during-context-swit.patch
Patch12: 0011-To-address-some-warnings-from-code-check-tool.patch
Patch13: 0012-disable-gpu-reset-in-context-switch.patch
Patch14: 0013-vgt-Fix-a-regression-introduce-by-rebasing-hv-vgt-sp.patch
Patch15: 0014-vgt-context-switch-refinement.patch
Patch16: 0015-i915-vgt-fix-for-bug-689-kernel-panic-in-Guest-Ubunt.patch
Patch17: 0016-Revert-vgt-skip-cmd-scan-in-a-mid-batch-preempted-re.patch
Patch18: 0017-Revert-vgt-use-virtual-head-as-last-scan-head-under-.patch
Patch19: 0018-Change-mask-size-to-32.patch
Patch20: 0019-Log-changes.patch
Patch21: 0020-Fix-command-parser-error-for-workloads.patch
Patch22: 0021-Only-find-submitted-execlists-in-CSB-emulation.patch
Patch23: 0022-vgt-execlist-idle-routine-refinement.patch
Patch24: 0023-vgt-fix-a-race-condition-between-irq-handler-and-eve.patch
Patch25: 0024-vgt-remove-0x20e4-from-register-switch-list-as-we-ha.patch
Patch26: 0025-Fix-a-typo.patch
Patch27: 0026-reset-execlist-structure-in-GPU-reset.patch
Patch28: 0027-Fix-a-use-after-free-condition.patch
Patch29: 0028-vgt-try-to-dump-ring-buffer-from-apeature-if-vgt_gma.patch
Patch30: 0029-vgt-handling-modifying-DE_RRMR-via-LRI-instructions.patch
Patch31: 0030-i915-vgt-workaround-for-bug-685-Dom0-S3-becomes-slow.patch
Patch32: 0031-vgt-factor-out-vgt_init_gtt-vgt_clean_gtt.patch
Patch33: 0032-vgt-mm-use-unified-shadow-page-mempool.patch
Patch34: 0033-drm-i915-bdw-WaProgramL3SqcReg1Default.patch
Patch35: 0034-drm-i915-PPGTT-Cacheability-Override.patch
Patch36: 0035-drm-i915-bdw-WaOCLCoherentLineFlush-bdw.patch
Patch37: 0036-drm-i915-bdw-WaDisableMidThreadPreempt-bdw.patch
Patch38: 0037-drm-i915-bdw-Remove-WaSwitchSolVfFArbitrationPriorit.patch
Patch39: 0038-vgt-clean-up-previous-WAs-and-definiations-after-int.patch
Patch40: 0039-vgt-change-some-register-policies.patch
Patch41: 0040-vgt-set-SNPCR-as-F_PT-on-BDW.patch
Patch42: 0041-vgt-remove-0xb10c-from-register-save-restore-list.patch
Patch43: 0042-vgt-change-the-name-of-guest-page-modification-trace.patch
Patch44: 0043-vgt-mm-support-partial-page-table-entry-access.patch
Patch45: 0044-vgt-return-the-actual-aperture-size-under-vgt-enviro.patch
Patch46: 0045-i915-add-missing-masked-operation-for-GEN8_FF_SLICE_.patch
Patch47: 0046-i915-move-pending-bdw-WAs-into-proper-place.patch
Patch48: 0047-vgt-add-missing-mask-opertation-for-some-registers.patch
Patch49: 0048-vgt-disable-s-r-some-slice-mmio-temporarily.patch
Patch50: 0049-i915-handle-register-0xfdc.patch
Patch51: 0050-vgt-let-dom0-take-control-of-register-0xfdc.patch
Patch52: 0051-vgt-Clear-the-bar-upper-32bit-data-while-create-hvm-.patch
Patch53: 0052-vgt-add-untracked-register-0x4dd4.patch
Patch54: 0053-Revert-vgt-remove-0x20e4-from-register-switch-list-a.patch
Patch55: 0054-vgt-tools-support-dump-preg-when-showing-register-in.patch
Patch56: 0055-vgt-tools-remove-GP-faults-related-code.patch
Patch57: 0056-Revert-vgt-handle-uninitialized-context-during-conte.patch
Patch58: 0057-vgt-perf-add-wp_-cycles-cnt.patch
Patch59: 0058-vgt-perf-re-enable-ppgtt_wp_-cycles-cnt.patch
Patch60: 0059-vgt-perf-add-spt_find_-hit-miss-_-cycles-cnt.patch
Patch61: 0060-vgt-perf-add-gpt_find_-hit-miss-_-cycles-cnt.patch
Patch62: 0061-vgt-mm-support-out-of-sync-PPGTT-shadow-page-table-o.patch
Patch63: 0062-vgt-perf-show-hlist-status-in-debugfs.patch
Patch64: 0063-vgt-perf-change-VGT_HASH_BITS-to-8.patch
Patch65: 0064-Fix-bug-for-indirect-display-vgtbuffer-feature.patch
Patch66: 0065-vgt-perf-ppgtt-oos-refinement.patch
Patch67: 0066-vgt-perf-account-oos-page-statistics.patch
Patch68: 0067-vgt-pvinfo-add-vgt-capability-in-pvinfo-page.patch
Patch69: 0068-vgt-perf-adjust-the-size-of-oos-page-pool-to-4096.patch
Patch70: 0069-i915-vgt-perf-bypass-forcewake-in-elsp-writes-when-r.patch
Patch71: 0070-vgt-address-a-corner-case-in-ppgtt-oos-refinement.patch
Patch72: 0071-vgt-out-of-sync-page-code-refinement.patch
Patch73: 0072-i915-user-library-can-specify-bsd-rings-through-exec.patch
Patch74: 0073-vgt-support-per-mmio-accounting.patch
Patch75: 0074-vgt-perf-refine-the-output-format-of-mmio-accounting.patch
Patch76: 0075-vgt-perf-trace-each-command-parsering-cost.patch
Patch77: 0076-vgt-increase-the-size-of-command-string-buffer-to-25.patch
Patch78: 0077-vgt-enable-ppgtt-out-of-sync-on-HSW.patch
Patch79: 0078-Callback-abstraction-and-refinement-for-vgtbuffer.patch
Patch80: 0079-Add-broadwell-support-for-vgtbuffer.patch
Patch81: 0080-vgt-perf-set-some-functions-as-inline-on-some-hot-pa.patch
Patch82: 0081-vgt-perf-introduce-command-parser-instruction-scan-b.patch
Patch83: 0082-vgt-perf-do-not-use-ip-buf-in-post-handle-entry.patch
Patch84: 0083-Remove-the-forcewake-workaround.patch
Patch85: 0084-vgt-fix-a-typo-in-command-parser-instruction-scan-bu.patch
Patch86: 0085-vgt-use-vzalloc-to-prevent-memory-allocation-failure.patch
Patch87: 0086-vgt-device-reset-fix-a-typo-in-vgt_request_force_rem.patch
Patch88: 0087-vgt-device-reset-refine-physical-device-reset-sequen.patch
Patch89: 0088-vgt-device-reset-let-guest-re-create-ppgtt-mm-during.patch
Patch90: 0089-vgt-device-reset-introduce-vgt_reset_execlist.patch
Patch91: 0090-vgt-enable-ring-when-execlist-mode-is-enabled.patch
Patch92: 0091-vgt-check-incomplete-guest-page-table-access.patch
Patch93: 0092-vgt-clear-fence-registers-after-fence-regions-alloca.patch
Patch94: 0093-vgt-change-int32_t-to-unsigned-long-in-get_gma_bb_fr.patch
Patch95: 0094-vgt-remove-register-0xb110-from-register-save-restor.patch
Patch96: 0095-vgt-refine-checking-incomplete-partial-access-sequen.patch
Patch97: 0096-vgt-cmd-scan-handling-for-lite-restore-preemption-an.patch
Patch98: 0097-Revise-the-condition-of-EXECLIST-idle-check.patch
Patch99: 0098-vgt-Optimize-emulation-of-el_status-register-to-enha.patch
Patch100: 0099-vgt-wait-active_to_idle-in-vgt_idle_execlist.patch
Patch101: 0100-vgt-remove-register-0x229c-from-register-save-restor.patch
Patch102: 0101-vgt-change-time-based-scheduler-timer-to-be-configur.patch
Patch103: 0102-vgt-adding-license-text-to-host.-ch.patch
Patch104: 0103-vgt-MIT-licence-compatible-changes.patch
Patch105: 0104-vgt-adding-license-text-to-i915_vgt.h.patch
Patch106: 0106-build-vgt-into-i915.patch
Patch107: 0107-vgt-disable-IPS.patch
Patch108: 0108-vgt-add-IPS_CTL-to-MMIO-audit-list.patch
Patch109: 0109-drm-use-a-dirty-workaround-to-remove-dependency-betw.patch
Patch110: 0110-vgt-cleanup-code.patch
Patch111: 0111-i915-vgt-and-xengt-dont-depend-on-each-other.patch
Patch112: 0112-Kconfig-configure-i915-vgt-as-LKM-by-default.patch
Patch113: 0113-i915-vgt-make-it-unloadable.patch
Patch114: 0114-vgt-set-hotplug-register-properly.patch
Patch115: 0115-kvmgt-porting-configuration-update.patch
Patch116: 0116-kvmgt-porting-MPT-support.patch
Patch117: 0117-kvmgt-porting-configuration-space-and-kvmgt-initiali.patch
Patch118: 0118-kvmgt-porting-aperture-and-opregion-intialization.patch
Patch119: 0119-config-remove-the-long-disappeared-XEN_INST_DECODER.patch
Patch120: 0120-config-add-essential-NAT-networking-support-which-is.patch
Patch121: 0121-config-rename-dom0-to-host-we-re-now-not-limited-to-.patch
Patch122: 0123-fix-bug822-i915-vgt-modulization-wrt.-both-XenGT-and.patch
Patch123: 0125-Fix-a-bug-that-initialize-the-opregion-for-kvm-host.patch
Patch124: 0127-vgt-set-port-A-hotplug-status-properly-for-HSW.patch
Patch125: 0128-vgt-handling-high-priority-events-are-no-longer-bloc.patch
Patch126: 0129-vgt-update-guest-CSB-entities-whenever-guest-read-re.patch
Patch127: 0130-i915-wait_for_atomic-will-spin-on-udelay-instead-of-.patch
Patch128: 0131-vgt-disable-GPU-master-irq-before-try-to-hold-spin_l.patch
Patch129: 0132-vgt-remove-pdev-lock-in-irq-handler.patch
Patch130: 0133-vgt-prevent-head-pointer-tail-pointer-submission.patch
Patch131: 0134-vgt-set-ppat-and-0x4dd4-as-F_PT.patch
Patch132: 0135-vgt-initialize-pdp-array-to-zero-before-usage.patch
Patch133: 0136-vgt-remove-klog-from-vgt-and-replace-with-trace.patch
Patch134: 0137-vgt-initial-guest-CSB-register-after-gpu-reset-under.patch
Patch135: 0138-Partial-fix-of-bug-728.patch
Patch136: 0139-vgt-ignore-update-Guest-PDP-once-a-context-was-submi.patch
Patch137: 0140-config-rename-config-3.18.0-to-config-4.1.0.patch
Patch138: 0141-vgt-Add-64bit-BAR-virtualization-support.patch
Patch139: 0144-Introduce-display.h.patch
Patch140: 0145-Introduce-gtt.h.patch
Patch141: 0146-Introduce-interrupt.h.patch
Patch142: 0147-Introduce-mmio.h.patch
Patch143: 0148-Introduce-four-header-files.patch
Patch144: 0149-shuffle-contents-of-execlist-contexts.patch
Patch145: 0150-Delete-SNB-register-save-restore-list-in-render.c.patch
Patch146: 0151-Reuse-MMIO-definition-of-i915.patch
Patch147: 0152-vgt-mmio-fix-a-typo.patch
Patch148: 0153-vgt-fix-Dom0-kernel-panic-during-show_debug.patch
Patch149: 0154-vgt-mmio-remove-SNB-and-IVB-related-MMIO-handler.patch
Patch150: 0155-vgt-mmio-split-vgt_base_reg_info.patch
Patch151: 0157-Move-hsw-ctx-switch-code-to-legacy.patch
Patch152: 0158-Move-global-variables-into-structures-in-render.c.patch
Patch153: 0159-Move-perf-sample-from-render.c-to-utility.c.patch
Patch154: 0160-Move-scheduler-related-code-in-render.c-to-sched.c.patch
Patch155: 0161-vgt-dispaly-use-virtual-vblank-for-VMs-all-time.patch
Patch156: 0162-Clean-up-some-usless-comments-introduced-dur-rebasin.patch
Patch157: 0163-Rename-configue-file-config-4.1.0-host-to-config-4.2.patch
Patch158: 0164-vgt-Fix-a-typo-pd-pb.patch
Patch159: 0165-Reuse-MMIO-definitions-in-i915-2.patch
Patch160: 0166-vgt-display-change-flip-done-interrupt-into-virtual-.patch
Patch161: 0167-vgt-destroy-sysfs-debugfs-out-of-spinlock-since-they.patch
Patch162: 0168-Update-XenGT-I-O-emulation-logic.patch
Patch163: 0169-host-mediation-use-spinlock-to-serialize-execution-o.patch
Patch164: 0172-kvmgt-rework-opregion-according-userspace-changes.patch
Patch165: 0181-Fix-the-KVMGT-reboot-issue-kvmgt-part.patch
Patch166: 0183-vgt-only-call-set-unset-mmio-range-for-guest.patch
Patch167: 0184-vgt-interrupt-convert-default-interrupt-event-policy.patch
Patch168: 0186-vgt-Keep-only-intel_lr_context_descriptor-for-calcul.patch
Patch169: 0191-vgt-remove-the-bogus-printk-message-about-virq.patch
Patch170: 0192-Remove-redundant-definition-in-vgt.patch
Patch171: 0194-Bug-fix-GTT-size-on-HSW-is-2MB-not-4MB.patch
Patch172: 0196-Show-correct-execlist-RB-content-in-dump-function.patch
Patch173: 0197-vgt-fix-debug-info-for-batch-buffer-in-execlist-mode.patch
Patch174: 0198-fix-some-misc-program-error.patch
Patch175: 0199-remove-validating-empty-context-checking-while-submi.patch
Patch176: 0200-vGT-Enable-bit-6-swizzling-in-i915.patch
Patch177: 0201-fix-some-error-report-by-klocwork.patch
Patch178: 0202-Refine-parser_exec_state_dump-to-dump-the-correct-cm.patch
Patch179: 0203-i915-vgt-disable-GuC-submission-when-vGPU-is-active.patch
Patch180: 0204-i915-vgt-extend-guest-vGPU-routines-to-SKL.patch
Patch181: 0205-i915-vgt-disable-DMC-firmware-loading-in-linux-guest.patch
Patch182: 0206-vgt-skl-basic-platform-awareness.patch
Patch183: 0207-vgt-skl-update-PCI-cfg-MSI-registers-address-for-SKL.patch
Patch184: 0208-vgt-skl-extend-some-gen8-commands-to-gen8.patch
Patch185: 0209-vgt-skl-introduce-new-command-3DSTATE_COMPONENT_PACK.patch
Patch186: 0210-vgt-skl-extend-DERRMR-patch-handler-to-gen8.patch
Patch187: 0211-vgt-fix-typo-AUX_CHENNEL-AUX_CHANNEL.patch
Patch188: 0212-vgt-skl-AUX-channel-interrupts-have-been-moved-into-.patch
Patch189: 0213-vgt-skl-intrducde-pipe-flip-done-interrupt-bit-defin.patch
Patch190: 0214-vgt-skl-introduce-untracked-registers.patch
Patch191: 0215-vgt-skl-disable-surface-base-range-check-for-SKL-tem.patch
Patch192: 0216-vgt-skl-add-SKL-DDI_AUX_CTL_B-C-D.patch
Patch193: 0217-vgt-skl-add-new-pixel-format-for-SKL.patch
Patch194: 0218-vgt-skl-add-SKL-forcewake-support-for-guest-VM.patch
Patch195: 0219-vgt-skl-Refine-DP-AUX-channel-emulation-for-SKL.patch
Patch196: 0220-vgt-skl-introduce-LCPLL1-2-write-handler.patch
Patch197: 0221-vgt-skl-introduce-DPLL_STATUS-read-handler.patch
Patch198: 0222-vgt-skl-emulate-power-well.patch
Patch199: 0223-vgt-skl-emulate-driver-mailbox-on-gen9.patch
Patch200: 0224-vgt-skl-add-plane-register-mapping-routines-for-SKL.patch
Patch201: 0225-vgt-skl-implement-basic-foreground-VM-switch.patch
Patch202: 0226-vgt-skl-disable-panel-fitter-by-default.patch
Patch203: 0227-vgt-do-not-read-untracked-and-non-accessed-registers.patch
Patch204: 0228-vgt-skl-add-SKL-s-r-register-list.patch
Patch205: 0229-vgt-skl-save-restore-mocs-registers.patch
Patch206: 0230-vgt-skl-do-not-perform-gen8-ring-switch-sequence-on-.patch
Patch207: 0231-vgt-reset-virtual-interrupt-registers-in-initializat.patch
Patch208: 0232-vgt-refine-execlist-status-emulation.patch
Patch209: 0233-vgt-change-the-register-type-of-0xe184-and-0xe100.patch
Patch210: 0234-Add-IS_PREEMPTION-check-when-update-vring-scan-state.patch
Patch211: 0235-Refine-cmd-parser-dump-prompt-message.patch
Patch212: 0236-vgt-skl-add-SKL-GT3-4-support-for-VCS2-ring.patch
Patch213: 0237-vgt-disable-guest-lite-restore-temporarily.patch
Patch214: 0238-vgt-skl-add-two-untracked-registers-after-enabling-h.patch
Patch215: 0239-vgt-skl-write-bit-0-of-0x4fdc-when-boot-up.patch
Patch216: 0240-Enable-the-initinalize-of-GPU-rps-powersave-in-Host.patch
Patch217: 0241-vgt-refine-cmd-parser-scan-pointer-update-method.patch
Patch218: 0242-Revert-vgt-disable-guest-lite-restore-temporarily.patch
Patch219: 0243-Fix-an-address-calculation-error-for-memcpy-in-gtt.c.patch
Patch220: 0244-Fix-a-potential-QEMU-crash-issue.patch
Patch221: 0245-vgt-trigger-shadow-when-the-lower-part-of-PTE-gets-u.patch
Patch222: 0246-Remove-i915_check_vgpu-in-intel_uncore_init.patch
Patch223: 0247-Upgrade-xen-vgt-domctl-interface-version-to-XEN-4.6.patch
Patch224: 0248-Update-config-for-4.3-rebasing.patch
Patch225: 0249-add-license-header-for-vgt_mgr.patch
Patch226: 0250-vgt-remove-unnecessary-ASSERT-from-aperture_gm.c.patch
Patch227: 0251-vgt-remove-ASSERT_VM-from-function-mmio_g2h_gmadr.patch
Patch228: 0252-vgt-Remove-ASSERT-in-handlers.c.patch
Patch229: 0253-vgt-Remove-ASSERT-from-render.c.patch
Patch230: 0254-vgt-Remove-ASSERT-from-display.c.patch
Patch231: 0255-vgt-Remove-ASSERT_VM-from-display.c.patch
Patch232: 0256-vgt-Remove-ASSERT-from-edid.c.patch
Patch233: 0257-vgt-security-remove-obsolete-command-handler.patch
Patch234: 0258-vgt-security-introduce-a-new-framework-for-command-a.patch
Patch235: 0259-vgt-security-take-use-the-new-command-address-audit-.patch
Patch236: 0260-vgt-security-add-render-registers-to-audit.patch
Patch237: 0261-vgt-security-special-registers-emulate-in-LRI.patch
Patch238: 0262-vgt-security-audit-force-nonpriv-access.patch
Patch239: 0263-vgt-security-detect-the-HW-reset-frequency.patch
Patch240: 0264-vgt-remove-ASSERT-from-cfg_space.c.patch
Patch241: 0265-vgt-remove-ASSERT-from-cmd_parser.c.patch
Patch242: 0266-Shadow-ring-buffer-implementation.patch
Patch243: 0267-shadow-privilege-batch-buffer.patch
Patch244: 0268-Enable-shadow-command-buffers.patch
Patch245: 0269-vgt-security-avoid-hang-cause-by-wrong-command.patch
Patch246: 0270-Kill-VMs-when-error-occurs.patch
Patch247: 0271-avoid-address-audit-failed-cause-by-invalid-surface-.patch
Patch248: 0272-EXECLIST-Code-cleanup.patch
Patch249: 0273-Cleanup-context-creation-function.patch
Patch250: 0274-Cleanup-context-submission-function.patch
Patch251: 0275-Fix-kernel-panic-caused-by-element-switch.patch
Patch252: 0276-Enlarge-the-workload-submission-queue.patch
Patch253: 0277-send-cs-interrupts-only-to-the-render-owner.patch
Patch254: 0278-lazy-shadow-context.patch
Patch255: 0279-Kill-VM-for-out-of-memory-of-reserved-aperture.patch
Patch256: 0280-default-to-use-optimized-lazy-shadow.patch
Patch257: 0281-Fix-an-issue-due-to-unexpected-gcc-behavior.patch
Patch258: 0282-use-page-address-for-reserved-aperture.patch
Patch259: 0283-Fix-some-issues-in-command-parser-while-booting-on-h.patch
Patch260: 0284-be-able-to-get-va-for-reserved-aperture.patch
Patch261: 0285-Add-more-information-in-ctx-tracing.patch
Patch262: 0286-selective-update-shadow-context.patch
Patch263: 0287-vgt-security-audit-batch-buffer-range.patch
Patch264: 0288-vgt-fix-bug-836-issue.patch
Patch265: 0289-vgt-do-not-kill-when-fail-to-resize-the-mempool.patch
Patch266: 0291-vgt-check-scratch-page-to-avoid-guest-crash.patch
Patch267: 0292-vgt-skl-handle-SKL-forcewake-regs-correctly.patch
Patch268: 0294-vgt-skl-add-SKL-8-VM-support.patch
Patch269: 0296-Re-generate-config-4.3.0-host.patch
Patch270: 0297-vgt-remove-the-PM-interrupts-mask-when-dom0-run-into.patch
Patch271: 0298-Add-missing-register-VEBOX_HWS_PGA_GEN7-during-rebas.patch
Patch272: 0299-vgt-security-enable-shadow-security-feature-for-SKL.patch
Patch273: 0300-vgt-security-audit-force-nonpriv-access-for-SKL.patch
Patch274: 0301-vgt-fix-sys-kernel-vgt-control-igd_mmio-access-error.patch
Patch275: 0302-vgt-fix-sys-kernel-vgt-control-igd_mmio-write-error.patch
Patch276: 0303-remove-vmfb_mapping.patch
Patch277: 0304-Refactor-gem-vgtbuffer.patch
Patch278: 0305-gem-vgtbuffer-new-implementation.patch
Patch279: 0306-Re-enable-vgtbuffer.patch
Patch280: 0307-vgt-skl-Enable-panel-fitting-for-SKL-pipeline.patch
Patch281: 0308-Enable-PPAT-translation-on-BDW.patch
Patch282: 0309-vgt-Fix-miscalculation-of-shadow-page-table-referenc.patch
Patch283: 0310-vgt-Add-new-mmio-into-track-list-for-Windows-10.patch
Patch284: 0311-vgt-skl-correct-cmd-parser-logic-for-MI_DISPLAY_FLIP.patch
Patch285: 0312-Fix-a-crash-during-freeing-vgtbuffer-objects.patch
Patch286: 0313-vgt-skl-Set-default-vGPU-schedule-interval-to-1ms.patch
Patch287: 0314-Use-Aliasing-PPGTT-only-when-GVT-g-is-enabled.patch
Patch288: 0315-Fix-preempt-disable-enable-unsymmetry.patch
Patch289: 0316-vgt-call-_hvm_exit-only-for-guests.patch
Patch290: 0317-config-turn-vfio-on.patch
Patch291: 0319-vgt-skl-add-surface-format-decode.patch
Patch292: 0320-Change-PPAT-register-handler-method-from-F_PT-to-F_D.patch
Patch293: 0321-Optimize-and-reduce-PPAT-related-logs.patch
Patch294: 0322-shadow-indirect-ctx-and-batch-buffer-per-ctx.patch
Patch295: 0323-enable-shadow-indirect-ctx-and-batch-buffer-per-ctx.patch
Patch296: 0324-add-a-new-F_RDR-register-to-whitelist.patch
Patch297: 0325-implement-audit-function-for-mi_op_2f.patch
Patch298: 0326-add-a-new-kernel-module-parameter-vgt_cmd_audit.patch
Patch299: 0327-vgt-skl-enable-cmd-audit-for-skl.patch
Patch300: 0328-passthru-regs-remove-registers-not-used.patch
Patch301: 0329-passthru-regs-keep-PT-for-HSW.patch
Patch302: 0330-passthru-regs-redefine-access-policy.patch
Patch303: 0331-passthru-regs-bring-a-new-register-type-F_PT_RO.patch
Patch304: 0332-disallowed-invalid-command-submit-to-HW.patch
Patch305: 0333-redefine-access-policy-for-register-ring-ctl.patch
Patch306: 0334-ring-enable-bit-should-always-be-set-in-context.patch
Patch307: 0335-vgt-implemented-new-32bit-PPGTT-logic.patch
Patch308: 0336-Add-kvmgt-support-in-vgt_perf.patch
Patch309: 0337-vgt-Remove-shadow-ppgtt-creation-from-shadow-context.patch
Patch310: 0338-vgt-patch-to-fix-897-issue.patch
Patch311: 0339-add-new-registers-to-while-list-for-SKL.patch
Patch312: 0340-vgt-skl-remove-one-F_PT-reg-for-skl.patch
Patch313: 0341-vgt-skl-redefine-access-policy-for-reg-0x4ddc-and-0x.patch
Patch314: 0342-vgt-skl-redefine-access-policy-for-reg-0x20e0-and-0x.patch
Patch315: 0343-passthru-regs-disallow-F_PT-from-BDW.patch
Patch316: 0344-vgt-Perform-normal-r-w-while-trapped-address-is-neit.patch
Patch317: 0345-enable-shadow-and-audit-privileged-BB-in-BLT-ring.patch
Patch318: 0346-Handle-guest-GuC-enabling-and-dump-warning.patch
Patch319: 0347-Dump-warning-when-guest-is-scaling-a-plane.patch
Patch320: 0348-wait-for-intel_fbdev_initial_config-finished-before-.patch
Patch321: 0349-vgt-consolidate-the-tlb-control-handling-before-the-.patch
Patch322: 0350-skip-some-verification-for-LRI.patch
Patch323: 0351-Remove-the-incorrect-interrupt-register-from-reset-l.patch
Patch324: 0352-Default-load-16-loop-devices-in-4.3-config.patch
Patch325: 0353-add-more-registers-to-white-list.patch
Patch326: 0354-drm-i915-skl-Disable-coarse-power-gating-up-until-F0.patch
Patch327: 0355-Remove-incorrect-register-from-restore-list.patch
Patch328: 0356-set-primary-sprite-plane-tiling-after-getting-the-pi.patch
Patch329: 0357-vgt-skl-remove-unused-pre-bdw-platforms-reserved-mem.patch
Patch330: 0358-add-a-kernel-parameter-enable_vgtbuffer.patch
Patch331: 0359-create-shadow-ppgtt-before-submit-the-workload.patch
Patch332: 0360-Adjust-cmd-length-correctly-for-NOOP.patch
Patch333: 0361-Remove-the-handling-of-cmd-buffer-resubmission.patch
Patch334: 0362-Remove-vgt_sysfs_lock-from-vgt_create_instance.patch
Patch335: 0363-fix-an-compile-warning.patch
Patch336: 0364-Fix-a-type-mismatch-warning-for-function-set_memory_.patch
Patch337: 0365-Fix-compile-warning-of-Wno-format.patch
Patch338: 0366-Compile-i915-vgt-with-Werror.patch
Patch339: 0368-Revert-Remove-the-handling-of-cmd-buffer-resubmissio.patch
Patch340: 0369-Revert-fix-an-compile-warning.patch
Patch341: 0370-Remove-the-handling-of-cmd-buffer-resubmission.patch
Patch342: 0371-i915-vgt-modulization-release-MPT-symbol-on-vgt-init.patch
Patch343: 0372-Replace-drm_gem_object_unreference-with-the-unlocked.patch
Patch344: 0373-Fix-an-logic-issue-in-ppgtt_allocate_oos_page.patch
Patch345: 0374-skl-fix-tiling-info-settings-in-fb-decoder.patch
Patch346: 0375-skl-fix-stride-calculation.patch
Patch347: 0376-Fix-the-el-context-find-logic-in-vgt.patch
Patch348: 0377-Move-the-extra-NOOPs-update-before-submittion-to-avo.patch
Patch349: 0378-vgt-remove-waitqueue_active-check-in-xen-mpt-module.patch
Patch350: 0379-avoid-ring-scan-error-for-shadow-indirect-ctx.patch
Patch351: 0380-don-t-sync-shadow-buffer-address-to-guest.patch
Patch352: 0381-Fix-a-compiling-warning.patch
Patch353: 0382-fix-for-bug-976.patch
Patch354: 0383-Disable-PG-on-SKL-as-a-temp-workaround.patch
Patch355: 0384-Fix-some-compiling-error-when-disabling-GVT-g.patch
Patch356: 0385-Enable-GVT-g-only-on-x86_64-platform.patch
Patch357: 0386-Fix-a-bug-wrong-condition-statement.patch
Patch358: 0387-add-a-parameter-vgt_hold_forcewake-for-vgt-to-hold-f.patch
Patch359: 0389-SBI-read-cache-miss-issue-fix.patch
Patch360: 0390-add-an-i915-option-gen9_pg_wa_enable.patch
Patch361: 0391-Add-code-to-avoid-log-flood-of-msi-inject-failure.patch
Patch362: 0392-Fix-code-bug-in-function-vgt_el_slots_next_sched.patch
Patch363: 0393-check-if-engine-is-supported-in-CTX_PTR-handler.patch
Patch364: 0394-support-guest-preemption-lite-restore-disable-enable.patch
Patch365: 0395-Fix-a-bug-in-preemption-disable-implementation.patch
Patch366: 0396-deferred-CMD-patching-mechanism-is-no-need-for-indir.patch
Patch367: 0397-create-a-dummy-guest-switch-to-avoid-lite-restore-fl.patch
Patch368: 0398-vgt-centrelized-kernel-parameter-check.patch
Patch369: 0399-vgt-enable-render_engine_reset-for-SKL.patch
Patch370: 0400-vgt-skl-fix-windows-guest-driver-upgrade-issue.patch
Patch371: 0401-vgt-debug-print-schedule-and-blank-time.patch
Patch372: 0402-vgt-debug-dump-debug-information-for-specific-guest.patch
Patch373: 0403-vgt-debug-leverage-the-new-debug-funtion.patch
Patch374: 0404-Add-64-bpp-RGB-support-for-Windows-10-guests.patch
Patch375: 0405-VGT-Fix-wrong-sprite-plane-format.patch
Patch376: 0406-vgt-stop-drop-the-frame-while-tile-format-isn-t-alig.patch
Patch377: 0407-vgt-add-more-registers-into-track-list-for-SKL.patch
Patch378: 0408-refine-vgtbuffer-size-calculation.patch
Patch379: 0409-Separate-GVT-g-host-RPS-threshold-parameters-with-na.patch
Patch380: 0410-Refine-the-RPS-thresholds-with-GVT-g.patch
Patch381: 0411-vgt-always-update-the-shadow-indirect_ctx-bb_per_ctx.patch
Patch382: 0412-vgt-remove-the-asserts-during-reset-to-make-CPU-core.patch
Patch383: 0413-temporay-workaround-for-bug-1136-on-kernel-4.3.patch
Patch384: 0414-vgt-fix-guest-fail-to-read-EDID-leading-to-black-gue.patch
Patch385: 0415-Revert-Add-64-bpp-RGB-support-for-Windows-10-guests.patch
Patch386: 0416-Revert-VGT-Fix-wrong-sprite-plane-format.patch
Patch387: 0417-vgt-refine-SKL-MOCS-save-restore-policy.patch
Patch388: 0418-Add-64-bpp-RGB-support-for-Windows-10-guests.patch
Patch389: 0419-VGT-Fix-wrong-sprite-plane-format.patch
Patch390: 0420-vgt-disable-sprite-plane.patch
Patch391: 0421-vgt-disable-sprite-conrtol-for-PIPE-B-and-C.patch
Patch392: 0422-vgt-delete-unused-function-fix-build-error.patch
Patch393: 0423-Support-USB-to-SATA-device-as-startup-disk.patch
Patch394: 0424-vgt-fix-wrong-stride-value-of-sprite-plane.patch
Patch395: 0425-vgt-add-render-CNTR-and-THRSH-regs-to-handle-list.patch
Patch396: 0426-vgt-qos-add-the-cap-control-interface.patch
Patch397: 0427-vgt-qos-add-some-statistics-routine-for-cap-control.patch
Patch398: 0428-vgt-qos-factor-out-the-scheduler.patch
Patch399: 0429-vgt-qos-add-sysfs-for-QoS-statistics.patch
Patch400: 0430-vgt-qos-implement-cap-control.patch
Patch401: 0431-vgt-qos-add-trace-function.patch
Patch402: 0432-vgt-qos-add-debugfs-for-QoS-statistics.patch
Patch403: 0433-avoid-unnecessary-context-switch.patch
Patch404: 0434-vgt-add-two-more-untracked-register-after-apply-the-.patch
Patch405: 0435-Add-mmio-handler-for-GEN6_MBCTL.patch
Patch406: 0436-fix-typo-in-mbctl_write-function.patch
Patch407: 0437-vgt-TDR-Generalise-common-GPU-engine-reset-code.patch
Patch408: 0438-vgt-TDR-disable-debug-dump-information-during-reset.patch
Patch409: 0439-vgt-TDR-GTT-table-should-not-be-released-during-emul.patch
Patch410: 0440-vgt-TDR-refine-idle-engine-hang-code.patch
Patch411: 0441-vgt-TDR-disable-render-between-hw-reset-and-guest-td.patch
Patch412: 0442-vgt-TDR-refine-ring-hang-logic.patch
Patch413: 0443-vgt-TDR-refine-the-print-info-during-reset.patch
Patch414: 0444-vgt-qos-keep-fairness-round-robin-after-longest-unsc.patch
Patch415: 0445-vgt-inject-sanitized-pipe_control-user_interrupt-to-.patch
Patch416: 0446-vgt-add-irq-lifecycle-and-vm-switch-trace-log.patch
Patch417: 0448-vgt-implementation-support-for-lazy-context.patch
Patch418: 0449-Revert-vgt-implementation-support-for-lazy-context.patch
Patch419: 0450-vgt-defer-shadow-ppgtt-destroy-after-queued-ctx-comp.patch
Patch420: 0451-vgt-Refined-for-lazy-context-corner-case.patch
Patch421: build-mipi-dsi-as-a-module.patch
Patch422: xengt-iommu.patch
Patch423: xengt-build.patch
Patch424: drm-build.patch
Patch425: i915-xengt-dependency.patch
Patch426: build-system-update.patch
Patch427: fix-build-warnings.patch
Patch428: port-limit-on-hvm-memory-mapping.patch
Patch429: vgt-fix-opregion-mapping-size.patch
Patch430: vgt-make-force-primary-work.patch
Patch431: vgt-add-hashing-gtt-framebuffer.patch
Patch432: vgt-fix-vgtbuffer-ioctl.patch
Patch433: vgtbuffer-round-up-y-tiled-size.patch
Patch434: vgt-adjust-default-parameters.patch
Patch435: setup_gtt_use_vzalloc.patch
Patch436: setup_gtt_don_t_use_wc_page.patch
Patch437: vgt_el_create_shadow_ppgtt_squash_warning.patch
Patch438: vgt_fix_mapping.patch
Patch439: vgt_check_for_out_of_range_gpa.patch
Patch440: add-configuration-files.patch
Patch441: adjust-logging.patch
Patch442: blacklist_i915.patch
Patch443: xen-4.7-compat.patch
Patch444: get_domctl_interface_version.patch
Patch445: use-printk-for-ctx-check-logging.patch
Patch446: 0001-xengt-add-dm_ops-definitions-from-Xen.patch
Patch447: 0002-xengt-convert-hvm_ops-to-dm_ops.patch
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: kernel-devel

%description
%{vendor_name} %{driver_name} device drivers.

%prep
%autosetup -p1

%build
ln mk/Kbuild Kbuild
%{?cov_wrap} %{__make} %{?_smp_mflags} -C /lib/modules/%{kernel_version}/build M=$(pwd) modules 

%install
rm -rf %{buildroot}
%{?cov_wrap} %{__make} -C /lib/modules/%{kernel_version}/build M=$(pwd) INSTALL_MOD_PATH=%{buildroot} INSTALL_MOD_DIR=%{module_dir} DEPMOD=/bin/true modules_install

# Flatten hierarchy
mv %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}/drivers/gpu/drm/i915/*.ko %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}
mv %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}/drivers/gpu/drm/*.ko %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}
mv %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}/drivers/xen/*.ko %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}
find %{buildroot}/lib/modules/%{kernel_version}/%{module_dir}/ -mindepth 1 -type d -delete

# mark modules executable so that strip-to-file can strip them
find %{buildroot}/lib/modules/%{kernel_version} -name "*.ko" -type f | xargs chmod u+x

mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 644 gvt-g-whitelist ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 644 gvt-g-monitor.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/modprobe.d
install -m 644 i915.conf ${RPM_BUILD_ROOT}%{_sysconfdir}/modprobe.d/

%clean
rm -rf %{buildroot}

%package modules
Summary: %{vendor_name} %{driver_name} drivers
Group: System Environment/Kernel
Requires: %{name}-%{modules_package} = %{version}-%{release}
Requires: %{name}-userspace = %{version}-%{release}

%description modules
Meta-package for automatic upgrades to the latest %{vendor_name}
%{driver_name} driver.

%files modules

%package %{modules_package}
Summary: %{vendor_name} %{driver_name} device drivers
Group: System Environment/Kernel
Requires: kernel-uname-r = %{kernel_version}
%if 0%{?fedora} >= 17 || 0%{?rhel} >= 7
Requires(post): /usr/sbin/depmod
Requires(postun): /usr/sbin/depmod
%else
Requires(post): /sbin/depmod
Requires(postun): /sbin/depmod
%endif

%description %{modules_package}
%{vendor_name} %{driver_name} device drivers for the Linux Kernel
version %{kernel_version}.

%post %{modules_package}
/sbin/depmod %{kernel_version}
mkinitrd -f /boot/initrd-%{kernel_version}.img %{kernel_version}

%postun %{modules_package}
/sbin/depmod %{kernel_version}
mkinitrd -f /boot/initrd-%{kernel_version}.img %{kernel_version}

%files %{modules_package}
%defattr(-,root,root,-)
/lib/modules/%{kernel_version}/*/*.ko
%doc

%package userspace
Summary: %{vendor_name} %{driver_name} userspace
Group: System Environment/Base

%description userspace
%{vendor_name} %{driver_name} Userspace components

%files userspace
%defattr(-,root,root,-)
%{_sysconfdir}/gvt-g-whitelist
%{_sysconfdir}/gvt-g-monitor.conf
%{_sysconfdir}/modprobe.d/i915.conf

%changelog
