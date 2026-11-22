| cell | gate | A (ABBA) | B (ABBA) | A/A | T | ABBA B/A | conf B/A | verdict |
|---|---|---|---|---|---|---|---|---|
| add_path_export_staging/deny_best/256/send_max_1 | gate | 85.935 us | 88.254 us | 1.005 | 1.020 | 1.027 | 1.029 | FAIL |
| add_path_export_staging/deny_best/256/send_max_4 | gate | 88.181 us | 90.847 us | 1.001 | 1.020 | 1.030 | 1.023 | FAIL |
| add_path_export_staging/deny_best/64/send_max_1 | gate | 30.888 us | 32.250 us | 1.010 | 1.020 | 1.044 | 1.038 | FAIL |
| add_path_export_staging/deny_best/64/send_max_4 | gate | 33.994 us | 35.343 us | 1.016 | 1.026 | 1.040 | 1.033 | FAIL |
| add_path_export_staging/deny_best/8/send_max_1 | gate | 13.638 us | 14.438 us | 1.063 | 1.073 | 1.059 | 1.044 | PASS |
| add_path_export_staging/deny_best/8/send_max_4 | gate | 16.390 us | 17.239 us | 1.046 | 1.056 | 1.052 | 1.035 | PASS |
| add_path_export_staging/permit_all/256/send_max_1 | gate | 72.419 us | 75.472 us | 1.003 | 1.020 | 1.042 | 1.047 | FAIL |
| add_path_export_staging/permit_all/256/send_max_4 | gate | 74.415 us | 77.496 us | 1.001 | 1.020 | 1.041 | 1.050 | FAIL |
| add_path_export_staging/permit_all/64/send_max_1 | gate | 24.599 us | 25.855 us | 1.023 | 1.033 | 1.051 | 1.051 | FAIL |
| add_path_export_staging/permit_all/64/send_max_4 | gate | 26.627 us | 27.993 us | 1.018 | 1.028 | 1.051 | 1.052 | FAIL |
| add_path_export_staging/permit_all/8/send_max_1 | gate | 9.260 us | 9.844 us | 1.093 | 1.103 | 1.063 | 1.071 | PASS |
| add_path_export_staging/permit_all/8/send_max_4 | gate | 11.178 us | 11.852 us | 1.072 | 1.082 | 1.060 | 1.073 | PASS |
| adj_rib_in_insert/10000 | gate | 534.023 us | 540.979 us | 1.023 | 1.033 | 1.013 | 1.037 | PASS |
| adj_rib_in_insert/100000 | report | 7.364 ms | 5.759 ms | 1.651 | 1.661 | 0.782 | 0.963 | report (PASS) |
| adj_rib_in_insert/500000 | report | 41.999 ms | 43.575 ms | 1.136 | 1.146 | 1.038 | 0.931 | report (PASS) |
| adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1 | gate | 42.853 us | 42.214 us | 1.014 | 1.024 | 0.985 | 0.983 | PASS |
| adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1000 | gate | 3.434 ms | 3.481 ms | 0.988 | 1.023 | 1.014 | 0.992 | PASS |
| adj_rib_out_family_gauge/homogeneous_route_server_second_pass/256 | gate | 833.455 us | 840.196 us | 0.985 | 1.026 | 1.008 | 0.994 | PASS |
| adj_rib_out_family_gauge/homogeneous_route_server_second_pass/64 | gate | 233.678 us | 234.187 us | 0.997 | 1.020 | 1.002 | 0.995 | PASS |
| adj_rib_out_family_gauge/homogeneous_route_server_second_pass/8 | gate | 63.140 us | 62.878 us | 1.008 | 1.020 | 0.996 | 0.988 | PASS |
| attr_decode/as_set_revised/1 | gate | 91.8 ns | 93.1 ns | 1.026 | 1.036 | 1.014 | 0.961 | PASS |
| attr_decode/rich/11 | gate | 346.1 ns | 345.5 ns | 0.982 | 1.028 | 0.998 | 1.005 | PASS |
| attr_decode/typical/6 | gate | 166.6 ns | 165.0 ns | 0.979 | 1.032 | 0.991 | 1.002 | PASS |
| attr_decode_revised/rich/11 | gate | 348.2 ns | 339.0 ns | 0.935 | 1.080 | 0.973 | 0.979 | PASS |
| attr_decode_revised/typical/6 | gate | 178.3 ns | 167.2 ns | 0.969 | 1.042 | 0.938 | 0.949 | WIN |
| attr_encode/rich/11 | gate | 377.8 ns | 376.1 ns | 1.027 | 1.037 | 0.995 | 0.989 | PASS |
| attr_encode/typical/6 | gate | 62.1 ns | 63.0 ns | 1.021 | 1.031 | 1.013 | 1.039 | PASS |
| attr_intern/many_unique/10000 | gate | 128.329 us | 131.896 us | 0.998 | 1.020 | 1.028 | 1.039 | FAIL |
| attr_intern/rich_independent_equal/10000 | gate | 382.898 us | 386.646 us | 1.002 | 1.020 | 1.010 | 1.013 | PASS |
| attr_intern/rich_shared_arc/10000 | gate | 40.327 us | 76.507 us | 1.572 | 1.582 | 1.897 | 1.882 | FAIL |
| attr_intern/typical_independent_equal/10000 | gate | 132.510 us | 131.525 us | 1.007 | 1.020 | 0.993 | 1.006 | PASS |
| attr_intern/typical_independent_equal/100000 | gate | 1.675 ms | 1.667 ms | 0.990 | 1.020 | 0.995 | 1.007 | PASS |
| attr_intern/typical_shared_arc/10000 | gate | 40.521 us | 76.121 us | 1.402 | 1.412 | 1.879 | 1.904 | FAIL |
| attr_intern/typical_shared_arc/100000 | gate | 956.844 us | 893.361 us | 0.903 | 1.117 | 0.934 | 0.492 | PASS |
| bulk_initial_load/10000 | gate | 1.678 ms | 1.715 ms | 0.994 | 1.020 | 1.022 | 1.025 | FAIL |
| bulk_initial_load/100000 | gate | 28.458 ms | 26.442 ms | 0.887 | 1.137 | 0.929 | 1.089 | PASS |
| distribute_fanout/no_policy/1 | gate | 45.864 us | 44.822 us | 1.007 | 1.020 | 0.977 | 0.984 | PASS |
| distribute_fanout/no_policy/256 | gate | 829.420 us | 839.658 us | 0.993 | 1.020 | 1.012 | 1.000 | PASS |
| distribute_fanout/no_policy/64 | gate | 235.917 us | 237.012 us | 0.995 | 1.020 | 1.005 | 0.990 | PASS |
| distribute_fanout/no_policy/8 | gate | 66.006 us | 65.389 us | 1.005 | 1.020 | 0.991 | 0.984 | PASS |
| distribute_fanout/with_modifying_policy/1 | gate | 57.457 us | 56.671 us | 1.015 | 1.025 | 0.986 | 0.987 | PASS |
| distribute_fanout/with_modifying_policy/256 | gate | 878.253 us | 886.500 us | 0.992 | 1.020 | 1.009 | 0.995 | PASS |
| distribute_fanout/with_modifying_policy/64 | gate | 256.876 us | 257.687 us | 0.994 | 1.020 | 1.003 | 0.991 | PASS |
| distribute_fanout/with_modifying_policy/8 | gate | 78.991 us | 78.525 us | 1.007 | 1.020 | 0.994 | 0.992 | PASS |
| distribute_fanout/with_policy/1 | gate | 51.530 us | 50.766 us | 1.004 | 1.020 | 0.985 | 0.976 | PASS |
| distribute_fanout/with_policy/256 | gate | 950.198 us | 951.295 us | 0.993 | 1.020 | 1.001 | 0.981 | PASS |
| distribute_fanout/with_policy/64 | gate | 268.436 us | 267.816 us | 0.994 | 1.020 | 0.998 | 0.978 | PASS |
| distribute_fanout/with_policy/8 | gate | 74.620 us | 74.196 us | 1.004 | 1.020 | 0.994 | 0.984 | PASS |
| failover_encode/announce_only/32 | gate | 185.267 us | 185.882 us | 0.986 | 1.024 | 1.003 | 0.989 | PASS |
| failover_encode/announce_only/8 | gate | 122.195 us | 122.276 us | 0.993 | 1.020 | 1.001 | 0.991 | PASS |
| failover_encode/mixed/32 | gate | 717.158 us | 720.047 us | 0.997 | 1.020 | 1.004 | 0.996 | PASS |
| failover_encode/mixed/8 | gate | 256.469 us | 255.146 us | 0.993 | 1.020 | 0.995 | 0.960 | PASS |
| grouped_dirty_resync/proof_backed/65536 | gate | 154.544 ms | 152.467 ms | 1.045 | 1.055 | 0.987 | 0.990 | PASS |
| grouped_policy_denial_fanout/homogeneous_route_server/256 | gate | 7.280 ms | 7.161 ms | 1.001 | 1.020 | 0.984 | 0.984 | PASS |
| grouped_policy_denial_fanout/homogeneous_route_server/64 | gate | 1.449 ms | 1.422 ms | 1.000 | 1.020 | 0.982 | 0.978 | PASS |
| grouped_policy_denial_fanout/homogeneous_route_server/8 | gate | 202.761 us | 199.951 us | 1.004 | 1.020 | 0.986 | 0.987 | PASS |
| grouped_withdrawal_fanout/homogeneous_route_server/64/1000 | gate | 3.259 ms | 3.341 ms | 0.977 | 1.033 | 1.025 | 1.007 | PASS |
| grouped_withdrawal_fanout/homogeneous_route_server/64/256 | gate | 799.186 us | 815.619 us | 0.983 | 1.028 | 1.021 | 1.006 | PASS |
| grouped_withdrawal_fanout/homogeneous_route_server/64/64 | gate | 234.035 us | 238.304 us | 0.989 | 1.021 | 1.018 | 1.013 | PASS |
| grouped_withdrawal_fanout/homogeneous_route_server/64/8 | gate | 72.981 us | 73.652 us | 1.003 | 1.020 | 1.009 | 1.014 | PASS |
| initial_table_deferred_group_join/16_joiners/65536 | gate | 583.832 ms | 577.600 ms | 1.002 | 1.020 | 0.989 | 0.992 | PASS |
| initial_table_deferred_group_join/4_joiners/65536 | gate | 152.239 ms | 150.338 ms | 1.002 | 1.020 | 0.988 | 0.987 | PASS |
| initial_table_group_join/1_sources/65536 | gate | 198.272 ms | 196.263 ms | 0.999 | 1.020 | 0.990 | 0.977 | PASS |
| initial_table_group_join/8_sources/65536 | gate | 198.590 ms | 195.457 ms | 1.003 | 1.020 | 0.984 | 0.983 | PASS |
| initial_table_peer_join/rr_client_ipv4_unicast/4096 | gate | 3.265 ms | 3.306 ms | 1.015 | 1.025 | 1.013 | 1.008 | PASS |
| initial_table_peer_join/rr_client_ipv4_unicast/65536 | gate | 82.472 ms | 72.219 ms | 1.011 | 1.021 | 0.876 | 0.876 | WIN |
| ixp_exact_export_fanout/distinct_remote_asns/256 | gate | 829.805 us | 838.867 us | 0.990 | 1.020 | 1.011 | 0.993 | PASS |
| ixp_exact_export_fanout/distinct_remote_asns/64 | gate | 235.720 us | 237.026 us | 0.995 | 1.020 | 1.006 | 0.996 | PASS |
| ixp_exact_export_fanout/distinct_remote_asns/8 | gate | 66.114 us | 65.501 us | 1.008 | 1.020 | 0.991 | 0.989 | PASS |
| ixp_exact_export_fanout/homogeneous_remote_asn/256 | gate | 832.676 us | 838.934 us | 0.990 | 1.020 | 1.008 | 0.991 | PASS |
| ixp_exact_export_fanout/homogeneous_remote_asn/64 | gate | 235.774 us | 237.094 us | 0.994 | 1.020 | 1.006 | 0.995 | PASS |
| ixp_exact_export_fanout/homogeneous_remote_asn/8 | gate | 66.035 us | 65.572 us | 1.003 | 1.020 | 0.993 | 0.984 | PASS |
| ixp_policy_regroup_resync/shared_plan/distinct_remote_asns/4096/64 | gate | 3.419 ms | 3.346 ms | 1.010 | 1.020 | 0.979 | 0.982 | PASS |
| ixp_policy_regroup_resync/shared_plan/homogeneous_remote_asn/4096/64 | gate | 3.440 ms | 3.362 ms | 1.007 | 1.020 | 0.977 | 0.977 | WIN |
| loc_rib_recompute/1 | gate | 104.4 ns | 107.6 ns | 0.937 | 1.077 | 1.031 | 1.027 | PASS |
| loc_rib_recompute/2 | gate | 112.4 ns | 293.3 ns | 0.859 | 1.174 | 2.610 | 1.032 | PASS |
| loc_rib_recompute/4 | gate | 129.3 ns | 132.2 ns | 0.940 | 1.074 | 1.023 | 1.018 | PASS |
| loc_rib_recompute/8 | gate | 161.9 ns | 337.1 ns | 0.998 | 1.020 | 2.082 | 1.013 | PASS |
| mp_exact_export_probe/distinct_shape/64 | gate | 22.728 us | 26.649 us | 0.989 | 1.021 | 1.172 | 0.986 | PASS |
| mp_exact_export_probe/rich_scalar/50 | gate | 28.946 us | 31.107 us | 1.005 | 1.020 | 1.075 | 1.011 | PASS |
| mp_exact_export_probe/same_shape/1 | gate | 388.3 ns | 421.8 ns | 1.006 | 1.020 | 1.086 | 0.987 | PASS |
| mp_exact_export_probe/same_shape/64 | gate | 2.842 us | 2.875 us | 1.008 | 1.020 | 1.012 | 1.007 | PASS |
| nlri_decode/1 | gate | 19.7 ns | 19.5 ns | 0.983 | 1.027 | 0.992 | 1.009 | PASS |
| nlri_decode/10 | gate | 101.6 ns | 101.7 ns | 0.995 | 1.020 | 1.001 | 1.001 | PASS |
| nlri_decode/100 | gate | 630.1 ns | 630.7 ns | 1.006 | 1.020 | 1.001 | 0.992 | PASS |
| nlri_decode/500 | gate | 2.791 us | 2.790 us | 1.003 | 1.020 | 0.999 | 0.995 | PASS |
| nlri_encode/1 | gate | 14.3 ns | 14.4 ns | 0.987 | 1.023 | 1.005 | 1.004 | PASS |
| nlri_encode/10 | gate | 32.2 ns | 32.2 ns | 0.830 | 1.215 | 1.000 | 0.942 | PASS |
| nlri_encode/100 | gate | 283.4 ns | 283.4 ns | 1.066 | 1.076 | 1.000 | 0.938 | PASS |
| nlri_encode/500 | gate | 1.388 us | 1.389 us | 1.002 | 1.020 | 1.001 | 0.933 | PASS |
| outbound_admission/add_path_shared_arc | gate | 364.381 us | 364.207 us | 1.003 | 1.020 | 1.000 | 0.986 | PASS |
| outbound_admission/distinct_values | gate | 4.737 ms | 4.712 ms | 1.006 | 1.020 | 0.995 | 1.003 | PASS |
| outbound_admission/equal_values | gate | 1.756 ms | 1.774 ms | 1.014 | 1.024 | 1.010 | 1.004 | PASS |
| outbound_admission/evpn_distinct_values | gate | 4.719 ms | 4.801 ms | 1.004 | 1.020 | 1.017 | 0.995 | PASS |
| outbound_admission/evpn_shared_arc | gate | 448.945 us | 437.022 us | 0.982 | 1.028 | 0.973 | 0.995 | PASS |
| outbound_admission/evpn_withdraw | gate | 382.495 us | 385.212 us | 0.995 | 1.020 | 1.007 | 0.998 | PASS |
| outbound_admission/ipv6_shared_arc | gate | 512.526 us | 513.116 us | 1.003 | 1.020 | 1.001 | 0.992 | PASS |
| outbound_admission/large_extended | gate | 54.188 ms | 74.963 ms | 1.053 | 1.063 | 1.383 | 1.010 | PASS |
| outbound_admission/large_standard | gate | 4.032 ms | 4.021 ms | 0.925 | 1.091 | 0.997 | 1.010 | PASS |
| outbound_admission/shared_arc | gate | 362.736 us | 359.936 us | 1.021 | 1.031 | 0.992 | 1.003 | PASS |
| outbound_admission/shared_arc_extended | gate | 357.509 us | 355.474 us | 1.017 | 1.027 | 0.994 | 1.005 | PASS |
| outbound_admission/vpn_distinct_values | gate | 5.802 ms | 5.870 ms | 1.002 | 1.020 | 1.012 | 1.007 | PASS |
| outbound_admission/vpn_shared_arc | gate | 732.200 us | 726.766 us | 0.998 | 1.020 | 0.993 | 1.004 | PASS |
| outbound_admission/vpn_withdraw | gate | 309.521 us | 311.478 us | 0.980 | 1.030 | 1.006 | 0.973 | PASS |
| outbound_admission/withdraw | gate | 165.567 us | 166.754 us | 1.000 | 1.020 | 1.007 | 1.004 | PASS |
| outbound_encode/distinct_values/100 | gate | 41.106 us | 41.561 us | 1.018 | 1.028 | 1.011 | 0.999 | PASS |
| outbound_encode/distinct_values/1000 | gate | 455.144 us | 455.823 us | 1.009 | 1.020 | 1.001 | 1.002 | PASS |
| outbound_encode/distinct_values/10000 | gate | 4.643 ms | 4.701 ms | 1.009 | 1.020 | 1.012 | 1.000 | PASS |
| outbound_encode/equal_values/100 | gate | 13.552 us | 13.454 us | 0.990 | 1.020 | 0.993 | 0.994 | PASS |
| outbound_encode/equal_values/1000 | gate | 163.266 us | 187.546 us | 1.011 | 1.021 | 1.149 | 1.007 | PASS |
| outbound_encode/equal_values/10000 | gate | 1.694 ms | 1.698 ms | 1.002 | 1.020 | 1.002 | 1.006 | PASS |
| outbound_encode/shared_arc/100 | gate | 3.723 us | 3.715 us | 0.992 | 1.020 | 0.998 | 1.067 | PASS |
| outbound_encode/shared_arc/1000 | gate | 27.959 us | 28.029 us | 0.998 | 1.020 | 1.002 | 0.982 | PASS |
| outbound_encode/shared_arc/10000 | gate | 275.725 us | 276.397 us | 0.988 | 1.022 | 1.002 | 0.996 | PASS |
| per_client_best_full_resync/ipv4_routes/4096/64 | gate | 254.883 ms | 246.939 ms | 0.986 | 1.024 | 0.969 | 0.984 | PASS |
| per_client_best_full_resync/ipv4_routes/4096/8 | gate | 27.083 ms | 27.027 ms | 1.001 | 1.020 | 0.998 | 1.002 | PASS |
| policy_regroup_resync/forced_per_peer/4096/1 | gate | 5.627 ms | 5.650 ms | 1.006 | 1.020 | 1.004 | 1.002 | PASS |
| policy_regroup_resync/forced_per_peer/4096/64 | gate | 227.336 ms | 230.783 ms | 1.006 | 1.020 | 1.015 | 1.008 | PASS |
| policy_regroup_resync/forced_per_peer/4096/8 | gate | 29.806 ms | 30.136 ms | 1.003 | 1.020 | 1.011 | 1.013 | PASS |
| policy_regroup_resync/forced_per_peer/65536/1 | gate | 173.264 ms | 169.314 ms | 1.020 | 1.030 | 0.977 | 0.980 | PASS |
| policy_regroup_resync/forced_per_peer/65536/64 | gate | 7.305 s | 6.936 s | 1.006 | 1.020 | 0.949 | 0.951 | WIN |
| policy_regroup_resync/forced_per_peer/65536/8 | gate | 960.550 ms | 926.162 ms | 1.003 | 1.020 | 0.964 | 0.940 | WIN |
| policy_regroup_resync/shared_plan/4096/1 | gate | 5.623 ms | 5.666 ms | 1.010 | 1.020 | 1.008 | 1.006 | PASS |
| policy_regroup_resync/shared_plan/4096/64 | gate | 3.401 ms | 3.339 ms | 1.028 | 1.038 | 0.982 | 0.983 | PASS |
| policy_regroup_resync/shared_plan/4096/8 | gate | 3.234 ms | 3.169 ms | 1.019 | 1.029 | 0.980 | 0.983 | PASS |
| policy_regroup_resync/shared_plan/65536/1 | gate | 172.790 ms | 170.576 ms | 1.000 | 1.020 | 0.987 | 0.977 | PASS |
| policy_regroup_resync/shared_plan/65536/64 | gate | 62.640 ms | 58.983 ms | 1.028 | 1.038 | 0.942 | 0.915 | WIN |
| policy_regroup_resync/shared_plan/65536/8 | gate | 62.679 ms | 58.427 ms | 1.026 | 1.036 | 0.932 | 0.941 | WIN |
| private_single_best_fanout/policy_peer_context/1 | report | 48.184 us | 48.834 us | 1.020 | 1.030 | 1.013 | 1.009 | report (PASS) |
| private_single_best_fanout/policy_peer_context/256 | report | 11.334 ms | 11.455 ms | 1.007 | 1.020 | 1.011 | 1.014 | report (PASS) |
| private_single_best_fanout/policy_peer_context/64 | report | 2.403 ms | 2.433 ms | 1.011 | 1.021 | 1.013 | 1.013 | report (PASS) |
| private_single_best_fanout/policy_peer_context/8 | report | 294.289 us | 298.147 us | 1.013 | 1.023 | 1.013 | 1.012 | report (PASS) |
| queued_announce_fanout/multi_source/one_per_message/64/1000 | gate | 6.180 ms | 6.291 ms | 0.996 | 1.020 | 1.018 | 1.002 | PASS |
| queued_announce_fanout/multi_source/one_per_message/64/256 | gate | 1.639 ms | 1.670 ms | 0.991 | 1.020 | 1.019 | 1.012 | PASS |
| queued_announce_fanout/multi_source/packed/64/1000 | gate | 6.169 ms | 6.259 ms | 0.989 | 1.021 | 1.015 | 1.015 | PASS |
| queued_announce_fanout/multi_source/packed/64/256 | gate | 1.597 ms | 1.630 ms | 0.992 | 1.020 | 1.021 | 1.012 | PASS |
| queued_announce_fanout/per_client_best/one_per_message/64/1000 | gate | 5.760 ms | 5.825 ms | 0.984 | 1.027 | 1.011 | 1.009 | PASS |
| queued_announce_fanout/per_client_best/one_per_message/64/256 | gate | 1.484 ms | 1.506 ms | 0.998 | 1.020 | 1.015 | 1.006 | PASS |
| queued_announce_fanout/per_client_best/packed/64/1000 | gate | 5.699 ms | 5.777 ms | 0.994 | 1.020 | 1.014 | 1.013 | PASS |
| queued_announce_fanout/per_client_best/packed/64/256 | gate | 1.439 ms | 1.463 ms | 0.994 | 1.020 | 1.016 | 1.014 | PASS |
| queued_announce_fanout/plain/one_per_message/64/1000 | gate | 3.437 ms | 3.469 ms | 0.978 | 1.033 | 1.009 | 0.999 | PASS |
| queued_announce_fanout/plain/one_per_message/64/256 | gate | 899.743 us | 906.873 us | 0.989 | 1.022 | 1.008 | 0.996 | PASS |
| queued_announce_fanout/plain/packed/64/1000 | gate | 3.422 ms | 3.418 ms | 0.971 | 1.040 | 0.999 | 0.989 | PASS |
| queued_announce_fanout/plain/packed/64/256 | gate | 855.666 us | 863.575 us | 0.996 | 1.020 | 1.009 | 0.990 | PASS |
| rib_pipeline/1000 | gate | 272.174 us | 268.807 us | 0.996 | 1.020 | 0.988 | 1.007 | PASS |
| rib_pipeline/10000 | gate | 2.686 ms | 2.668 ms | 1.014 | 1.024 | 0.993 | 0.988 | PASS |
| rib_pipeline/50000 | report | 19.857 ms | 21.708 ms | 1.160 | 1.170 | 1.093 | 1.520 | report (PASS) |
| route_refresh_group_member/1_sources/65536 | gate | 52.999 ms | 51.377 ms | 1.002 | 1.020 | 0.969 | 1.013 | PASS |
| route_refresh_group_member/8_sources/65536 | gate | 54.061 ms | 52.092 ms | 0.996 | 1.020 | 0.964 | 0.961 | WIN |
| update_build/1 | gate | 157.0 ns | 156.7 ns | 1.044 | 1.054 | 0.998 | 0.928 | PASS |
| update_build/10 | gate | 242.9 ns | 249.1 ns | 1.037 | 1.047 | 1.026 | 0.974 | PASS |
| update_build/100 | gate | 568.6 ns | 568.0 ns | 1.013 | 1.023 | 0.999 | 0.983 | PASS |
| update_build/500 | gate | 1.794 us | 1.840 us | 1.005 | 1.020 | 1.026 | 1.000 | PASS |
| update_build/ipv6_mp_add_path | gate | 167.9 ns | 170.4 ns | 1.012 | 1.022 | 1.015 | 1.014 | PASS |
| update_parse/1 | gate | 189.7 ns | 192.7 ns | 0.970 | 1.040 | 1.016 | 1.032 | PASS |
| update_parse/10 | gate | 281.7 ns | 278.3 ns | 0.986 | 1.024 | 0.988 | 1.000 | PASS |
| update_parse/100 | gate | 842.2 ns | 837.2 ns | 1.000 | 1.020 | 0.994 | 0.996 | PASS |
| update_parse/500 | gate | 3.151 us | 3.149 us | 0.964 | 1.048 | 0.999 | 0.992 | PASS |
| update_parse_revised/1 | gate | 208.8 ns | 210.4 ns | 0.971 | 1.040 | 1.007 | 0.978 | PASS |
| update_parse_revised/10 | gate | 293.0 ns | 291.2 ns | 0.990 | 1.021 | 0.994 | 0.994 | PASS |
| update_parse_revised/100 | gate | 856.5 ns | 857.0 ns | 1.004 | 1.020 | 1.001 | 0.977 | PASS |
| update_parse_revised/500 | gate | 3.167 us | 3.163 us | 0.998 | 1.020 | 0.999 | 0.990 | PASS |
| update_parse_revised/ipv6_mp_add_path | gate | 213.1 ns | 207.8 ns | 0.991 | 1.020 | 0.975 | 0.991 | PASS |
| update_parse_revised/ipv6_typical/1 | gate | 241.2 ns | 237.1 ns | 0.995 | 1.020 | 0.983 | 1.007 | PASS |
| update_parse_revised/ipv6_typical/100 | gate | 985.4 ns | 981.2 ns | 1.004 | 1.020 | 0.996 | 1.002 | PASS |
| validate_update | gate | 11.6 ns | 11.5 ns | 0.996 | 1.020 | 0.994 | 1.001 | PASS |

cells: 166 paired (159 gated), 0 candidate-only (report-only, unpaired)
candidate-only: none
cells missing a step (INVALID): none
gated FAIL: ['add_path_export_staging/deny_best/256/send_max_1', 'add_path_export_staging/deny_best/256/send_max_4', 'add_path_export_staging/deny_best/64/send_max_1', 'add_path_export_staging/deny_best/64/send_max_4', 'add_path_export_staging/permit_all/256/send_max_1', 'add_path_export_staging/permit_all/256/send_max_4', 'add_path_export_staging/permit_all/64/send_max_1', 'add_path_export_staging/permit_all/64/send_max_4', 'attr_intern/many_unique/10000', 'attr_intern/rich_shared_arc/10000', 'attr_intern/typical_shared_arc/10000', 'bulk_initial_load/10000']
gated WIN: 8
intruder samples: 0
VERDICT: FAIL
