if(COMMAND aps5_macos_skip)
    return()
endif()

function(aps5_macos_skip reason)
    foreach(name ${ARGN})
        if(NOT TEST ${name})
            message(FATAL_ERROR "macOS skip names a test that is not registered: ${name}")
        endif()
        set_property(TEST ${name} APPEND PROPERTY ENVIRONMENT "APS5_MACOS_SKIP=${reason}")
        set_property(TEST ${name} PROPERTY SKIP_RETURN_CODE 77)
    endforeach()
endfunction()

function(aps5_macos_skip_libc)
    if(NOT APPLE OR NOT BUILD_TESTING)
        return()
    endif()
    aps5_macos_skip("skipped, macOS compact unwind lookup misses this frame so the C++ exception is uncaught"
        application_heap_invalid_metadata)
    aps5_macos_skip("skipped, macOS has no SOCK_SEQPACKET so the log flush count cannot be observed" log_macros)
    aps5_macos_skip("skipped, macOS CI volume is case-insensitive so PS5 path case is not distinct" guest_path_case)
endfunction()

function(aps5_macos_skip_kernel)
    if(NOT APPLE OR NOT BUILD_TESTING)
        return()
    endif()
    aps5_macos_skip("skipped, macOS ModuleInfo leaves TLS and eh_frame empty" guest_module_info)
    aps5_macos_skip("skipped, macOS CI volume is case-insensitive so PS5 path case is not distinct" guest_filesystem)
    aps5_macos_skip("skipped, macOS has no POLLRDHUP so this UDP wait does not match" guest_udp)
    aps5_macos_skip("skipped, macOS guest socket pair aborts" guest_socket_pair)
endfunction()

function(aps5_macos_skip_video_out)
    if(NOT APPLE OR NOT BUILD_TESTING)
        return()
    endif()
endfunction()

function(aps5_macos_skip_agc)
    if(NOT APPLE OR NOT BUILD_TESTING)
        return()
    endif()
    aps5_macos_skip("skipped, macOS QoS does not refuse this priority request"
        agc_thread_priority_refused_rt
        agc_thread_priority_refused_high
        agc_driver_pm4_priority_refused)
    aps5_macos_skip("skipped, macOS profile writer failure was not propagated" agc_profile_output)
    aps5_macos_skip("skipped, MoltenVK portability or macOS host memory does not match this GPU test"
        agc_driver
        agc_shader_memory
        agc_structurizer
        agc_driver_flip
        agc_driver_graphics
        agc_driver_bda_device
        agc_driver_cmask_fast_clear
        agc_driver_alpha_to_coverage
        agc_driver_array_layer_target
        agc_driver_buffer_unaligned_base
        agc_driver_color1555_target
        agc_driver_compute_user_data_calls
        agc_driver_dcc_keys_first_write
        agc_driver_depth_compare_copy
        agc_driver_dpp16_operands
        agc_driver_dual_source_blend
        agc_driver_emulated_color_compare
        agc_driver_f32_constant_factor_tininess
        agc_driver_f32_denormal_flush
        agc_driver_f32_dot2_rounding
        agc_driver_f32_output_modifier
        agc_driver_float16_fma_rounding
        agc_driver_float16_misc
        agc_driver_float16_modifiers
        agc_driver_float16_rounding
        agc_driver_image_cache_bits
        agc_driver_image_srgb_load
        agc_driver_image_texel_status
        agc_driver_ldexp_f16_inline_constants
        agc_driver_ngg_vertex_wave_info
        agc_driver_packed_alu
        agc_driver_packed_unorm_color_target
        agc_driver_pixel_interlock
        agc_driver_pixel_uint16_export
        agc_driver_prepared_graphics
        agc_driver_prepared_shaders
        agc_driver_relative_ancillary
        agc_driver_sdwa_float_selectors
        agc_driver_sdwa_ldexp_f16
        agc_driver_srgb8_color_target
        agc_driver_storage_one_slice_alias
        agc_driver_swap_alt_blend
        agc_driver_vop2_modifier_forms
        agc_driver_vopc_compare_table
        agc_driver_emulated_color_compare_srgb_decode
        agc_structurizer_intersection_off
        agc_structurizer_iteration_selection_off
        agc_driver_pm4_failure
        agc_driver_flip_compute
        agc_driver_prepared_shaders_indirect
        agc_driver_prepared_shaders_uncached
        agc_driver_prepared_shaders_debug
        agc_driver_prepared_shaders_debug_failure
        agc_driver_prepared_shaders_deferred
        agc_driver_prepared_shaders_deferred_undecodable
        agc_driver_prepared_shaders_registered_workgroup_sync
        agc_driver_compute_user_data_calls_registered)
endfunction()
