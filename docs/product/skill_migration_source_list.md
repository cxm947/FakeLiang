# 技能卡迁移来源清单（B0）

> 生成：`python scripts/build_migration_source_list.py`。**禁止手改**：本页由注册表与 v2 契约推导，
> 改卡后重跑即同步；`--check` 会在漂移时报错。

## 汇总

| 项 | 数 |
|---|---|
| 注册表技能总数 | 35 |
| 自己承载方法契约（v2 carrier） | 22 |
| 作为实现变体被承接（旧编号保留兼容） | 13 |
| 尚未有 v2 承接 | 0 |

## 逐卡去向

| 原卡 | 代际去向 | 承接卡 | 变体 | 方法 | 说明 |
|---|---|---|---|---|---|
| `pre.nmap_tcp_probe` | carrier | `pre.nmap_tcp_probe` | - | `method.observe.network_reachability` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.wmi_firewall_off` | carried_as_variant | `exploit.netexec_firewall_off` | instrumentation_route | `method.remote_disable_defenses` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `exploit.netexec_firewall_off` | carrier | `exploit.netexec_firewall_off` | - | `method.remote_disable_defenses` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.tongda_oa_include_rce` | carrier | `exploit.tongda_oa_include_rce` | - | `method.tongda_oa_include_rce` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.redis_unauth_write` | carrier | `exploit.redis_unauth_write` | - | `method.redis_unauth_key_write` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.laravel_ignition_rce` | carrier | `exploit.laravel_ignition_rce` | - | `method.laravel_ignition_rce` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.privileged_container_escape` | carrier | `exploit.privileged_container_escape` | - | `method.privileged_container_escape` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.suid_path_hijack` | carrier | `exploit.suid_path_hijack` | - | `method.suid_path_helper` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.kiwi_lsass_dump` | carrier | `exploit.kiwi_lsass_dump` | - | `method.lsass_domain_credential_dumping` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.comsvcs_minidump` | carried_as_variant | `exploit.kiwi_lsass_dump` | dump_then_transfer | `method.lsass_domain_credential_dumping` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `exploit.pypykatz_parse` | carried_as_variant | `exploit.kiwi_lsass_dump` | dump_then_transfer | `method.lsass_domain_credential_dumping` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `exploit.wmic_remote_cmd` | carried_as_variant | `exploit.impacket_psexec_cmd` | instrumentation_route | `method.windows_credential_remote_execution` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `exploit.impacket_psexec_cmd` | carrier | `exploit.impacket_psexec_cmd` | - | `method.windows_credential_remote_execution` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `exploit.impacket_wmiexec_cmd` | carried_as_variant | `exploit.impacket_psexec_cmd` | instrumentation_route | `method.windows_credential_remote_execution` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `session.ssh_via_redis` | carried_as_variant | `exploit.redis_unauth_write` | session_delivery | `method.redis_unauth_key_write` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `session.webshell_via_laravel` | carried_as_variant | `exploit.laravel_ignition_rce` | session_delivery | `method.laravel_ignition_rce` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `session.msf_via_credentials` | carried_as_variant | `exploit.impacket_psexec_cmd` | session_delivery | `method.windows_credential_remote_execution` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `session.root_via_suid` | carried_as_variant | `exploit.suid_path_hijack` | session_delivery | `method.suid_path_helper` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `post.channel_echo` | carrier | `post.channel_echo` | - | `method.observe.channel_echo` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `session.msf_migrate` | carried_as_variant | `session.msf_adopt_native` | migrate_route | `method.session_handover` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `exploit.http_post_file` | carried_as_variant | `exploit.kiwi_lsass_dump` | dump_then_transfer | `method.lsass_domain_credential_dumping` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `pre.tool_present` | carrier | `pre.tool_present` | - | `method.observe.tool_presence` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.service_version` | carrier | `pre.service_version` | - | `method.observe.service_exposure` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.credential_valid` | carrier | `pre.credential_valid` | - | `method.observe.credential_validity` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.session_identity` | carrier | `pre.session_identity` | - | `method.observe.session_identity` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.netsecurity_firewall_state` | carrier | `pre.netsecurity_firewall_state` | - | `method.observe.defense_state` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.docker_inspect` | carrier | `pre.docker_inspect` | - | `method.observe.container_relation` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.cim_process_info` | carrier | `pre.cim_process_info` | - | `method.observe.process_service_info` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.impacket_scm_query` | carrier | `pre.impacket_scm_query` | - | `method.observe.service_control_endpoint` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `pre.posix_path_access` | carrier | `pre.posix_path_access` | - | `method.observe.path_write` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `post.file_present` | carrier | `post.file_present` | - | `method.observe.file_presence` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `post.identity` | carrier | `post.identity` | - | `method.observe.identity` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `session.msf_adopt_native` | carrier | `session.msf_adopt_native` | - | `method.session_handover` | 这张卡自己承载方法契约（一个指定方法一张逻辑卡） |
| `session.msf_adopt_web` | carried_as_variant | `session.msf_adopt_native` | web_route | `method.session_handover` | 同一方法内的实现变体，旧编号保留兼容引用 |
| `session.msf_adopt_mount` | carried_as_variant | `session.msf_adopt_native` | mount_route | `method.session_handover` | 同一方法内的实现变体，旧编号保留兼容引用 |
