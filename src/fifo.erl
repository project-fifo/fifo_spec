-module(fifo).

-export_type([attr_list/0,
              key/0,
              keys/0,
              object/0,
              config/0,
              vm_config/0,
              vm_type/0,
              vm_state/0,
              vm_state_atom/0,
              log/0,
              value/0,
              matcher/0,
              uuid/0,
              obj/0,
              firewall_rule/0,
              smartos_fw_rule/0]).

-export_type([
              dataset/0,
              dataset_id/0,
              dtrace_id/0,
              dtrace/0,
              grouping_id/0,
              grouping/0,
              hypervisor/0,
              hypervisor_id/0,
              iprange/0,
              iprange_id/0,
              network/0,
              network_id/0,
              package/0,
              package_id/0,
              vm/0,
              vm_id/0
             ]).

-export_type([user/0,
              user_id/0,
              client_id/0,
              role/0,
              role_id/0,
              org/0,
              org_id/0,
              user_token_id/0,
              token/0,
              oauth_token_type/0,
              scope_list/0,
              scope_map/0,
              trigger/0,
              event/0
             ]).


-export_type([permission/0,
              comparer/0,
              number_comparer/0,
              set_comparer/0,
              element_comparer/0,
              permission_comparer/0]).

-export_type([sniffle_message/0,
              sniffle_dataset_message/0,
              sniffle_dtrace_message/0,
              sniffle_grouping_message/0,
              sniffle_hypervisor_message/0,
              sniffle_iprange_message/0,
              sniffle_network_message/0,
              sniffle_package_message/0,
              sniffle_vm_message/0,
              howl_message/0,
              chunter_message/0,
              snarl_message/0,
              snarl_user_message/0,
              snarl_role_message/0,
              snarl_org_message/0,
              snarl_acc_message/0,
              snarl_oauth_message/0
             ]).



-export_type([write_fsm_reply/0,
              read_fsm_reply/0,
              coverage_fsm_reply/0]).


-type key()::binary()|integer().

-type keys()::key()|[key()].

-type value()::binary()|number()|object()|jsxarray()|null|true|false.

-type object():: #{binary() => value()}.

-type jsxarray()::[value()].

-type user_token_id() :: user_id() | {token, Token::token()}.
-type realm() :: binary().

-type grouping_type() :: cluster | stack | none.

-type trigger() :: term().

-type log() :: {{integer(), integer(), integer()}, term()}.

%% Types for the different FiFo datasets
-type dataset() :: ft_dataset:dataset().
-type dataset_id() :: uuid().
-type dtrace_id() :: uuid().
-type dtrace() :: ft_dtrace:dtrace().
-type grouping_id() :: uuid().
-type grouping() :: ft_grouping:grouping().
-type hypervisor() :: ft_hypervisor:hypervisor().
-type hypervisor_id() :: uuid().
-type iprange() :: ft_iprange:iprange().
-type iprange_id() :: uuid().
-type network() :: ft_network:network().
-type network_id() :: uuid().
-type package() :: ft_package:package().
-type package_id() :: uuid().
-type vm() :: ft_vm:vm().
-type vm_id() :: uuid().

-type obj() :: ft_obj:obj().

-type org() :: ft_org:org().
-type org_id() :: uuid().
-type role() :: ft_role:role().
-type role_id() :: uuid().
-type user() :: ft_user:user().
-type user_id() :: uuid().
-type client_id() :: uuid().

-type oauth_token_type() :: access_codes | access_tokens | refresh_tokens.
-type token() :: binary() | {oauth_token_type(), binary()}.

-type event() :: atom().

-type permission() ::
        [binary()].

-type number_comparer() ::
        '>=' | '<=' | '>' | '<' | '=:=' | '=/='.

-type set_comparer() ::
        'subset' | 'superset' | 'disjoint'.

-type element_comparer() ::
        'element'.

-type permission_comparer() ::
        'allowed'.

-type comparer() ::
        number_comparer() |
        set_comparer() |
        element_comparer() |
        permission_comparer().

-type matcher_type() ::
        'must' | 'cant' | number().

-type permission_key() ::
        [binary() | {binary(), binary()}].

-type matcher() ::
        {matcher_type(), number_comparer(), Key::binary(), number()} |
        {matcher_type(), set_comparer(), Key::binary(), [term()]} |
        {matcher_type(), element_comparer(), Key::binary(), term()} |
        {matcher_type(), permission_comparer(), Key::permission_key(),
         [permission()]}.

-type attr_list() :: [{Key::keys(),
                       Value::value() | delete}].

-type vm_config() :: object().

-type config() :: object().

-type uuid() :: <<_:288>>.

-type vm_type() :: kvm | zone.

-type vm_state_atom() ::
        booting |
        shutting_down |
        running |
        stopped.

-type vm_state() ::
        binary().

-type backup_opt() :: term().

%%%===================================================================
%%%  Howl
%%%===================================================================

-type howl_message() ::
        ping |
        version |
        {msg, Channel::uuid(), Message::object()} |
        {msg, Messages::[{Channel::uuid(), Message::object()}]}.

%%%===================================================================
%%%  Chunter
%%%===================================================================


-type chunter_message() ::
        ping |
        version |
        update |
        {lock, LockID::binary()} |
        {release, LockID::binary()} |
        {machines, start, UUID::vm_id()} |
        {machines, start, UUID::vm_id(), Image::binary()} |
        {machines, stop, UUID::vm_id()} |
        {machines, stop, force, UUID::vm_id()} |
        {machines, reboot, UUID::vm_id()} |
        {machines, reboot, force, UUID::vm_id()} |
        {machines, snapshot, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, delete, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, rollback, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, store, UUID::vm_id(), SnapID::uuid(),
         ImgID::uuid()} |
        {machines, snapshot, store, UUID::vm_id(), SnapId::uuid(), Img::uuid(),
         Host::inet:ip_address() | inet:hostname(), Port::inet:port_number(),
         Bucket::binary(), AKey::binary(), SKey::binary(),
         Opts::[proplists:property()]} |
        {machines, backup, UUID::vm_id(), BackupID::uuid(),
         Opts::[backup_opt()]} |
        {machines, backup, restore, UUID::vm_id(), BackupID::uuid(),
         Opts::[backup_opt()]} |
        {machines, backup, delete, UUID::vm_id(), BackupID::uuid()} |
        {machines, service, enable | disable | clear | restart | refresh,
         UUID::vm_id(),  Service::uuid()} |
        {service, enable | disable | clear | refresh | restart,
         Service :: uuid()} |
        {machines, create,
         UUID::vm_id(),
         PSpec::package(),
         DSpec::dataset(),
         Config::config()} |
        {machines, delete, UUID::vm_id()} |
        {machines, update,
         UUID::vm_id(),
         PSpec::package() | undefined,
         Config::config()} |
        {fw, update, UUID::vm_id()}.

%%%===================================================================
%%%  Sniffle
%%%===================================================================
-type ac_user()::user_id() | undefined.

-type sniffle_message() ::
        ping |
        version |
        {s3, Type :: atom()} |
        {cloud, status}.

-type sniffle_dtrace_message() ::
        {dtrace, add, Name::binary(), Script::string()} |
        {dtrace, delete, ID::dtrace_id()} |
        {dtrace, get, ID::dtrace_id()} |
        {dtrace, list} |
        {dtrace, list, Requreiments::[matcher()], Full::boolean()} |
        {dtrace, name, ID::dtrace_id(), binary()} |
        {dtrace, uuid, ID::dtrace_id(), binary()} |
        {dtrace, script, ID::dtrace_id(), string()} |
        {dtrace, set_metadata, ID::dtrace_id(), attr_list()} |
        {dtrace, set_config, ID::dtrace_id(), attr_list()} |
        {dtrace, run, ID::dtrace_id(), Servers::[hypervisor()]}.

-type sniffle_vm_message() ::
        {vm, store, ac_user(), binary()} |
        {vm, backup, incremental, Vm::vm_id(), Parent::uuid(), BackupID::uuid(),
         Opts::[backup_opt()]} |
        {vm, backup, full,
         Vm::vm_id(), BackupID::uuid(), Opts::[backup_opt()]} |
        {vm, backup, restore, Vm::vm_id(), BackupID::uuid()} |
        {vm, backup, restore,
         ac_user(), Vm::vm_id(), BackupID::uuid(), Opts::[backup_opt()]} |
        {vm, backup, delete, Vm::vm_id(), BackupID::uuid(),
         Where::hypervisor|cloud} |
        {vm, service, enable, Vm::vm_id(), Service::binary()} |
        {vm, service, disable, Vm::vm_id(), Service::binary()} |
        {vm, service, clear, Vm::vm_id(), Service::binary()} |
        {vm, service, refresh, Vm::vm_id(), Service::binary()} |
        {vm, service, restart, Vm::vm_id(), Service::binary()} |
        {vm, log, Vm::vm_id(), Log::term()} |
        {vm, register, Vm::vm_id(), Hypervisor::binary()} |
        {vm, snapshot, Vm::vm_id(), Comment::binary()} |
        {vm, snapshot, delete, Vm::vm_id(), UUID::uuid()} |
        {vm, snapshot, rollback, Vm::vm_id(), UUID::uuid()} |
        {vm, snapshot, commit_rollback, Vm::vm_id(), UUID::uuid()} |
        {vm, snapshot, promote, Vm::vm_id(),
         SnapUUID::uuid(), Dataset::config()} |
        {vm, create, Package::binary(), Dataset::binary(), Config::config()} |
        {vm, dry_run, Package::binary(), Dataset::binary(), Config::config()} |
        {vm, update, ac_user(), Vm::vm_id(),
         Package::package_id() | undefined, Config::config()} |
        {vm, unregister, Vm::vm_id()} |
        {vm, get, Vm::vm_id()} |
        {vm, start, Vm::vm_id()} |
        {vm, delete, ac_user(), Vm::vm_id()} |
        {vm, stop, Vm::vm_id()} |
        {vm, reboot, Vm::vm_id()} |
        {vm, stop, force, Vm::vm_id()} |
        {vm, reboot, force, Vm::vm_id()} |
        {vm, owner, ac_user(), vm_id(), binary()} |
        {vm, state, vm_id(), binary()} |
        {vm, set_service, vm_id(), attr_list()} |
        {vm, set_backup, vm_id(), attr_list()} |
        {vm, set_snapshot, vm_id(), attr_list()} |
        {vm, set_metadata, vm_id(), attr_list()} |
        {vm, set_config, vm_id(), attr_list()} |
        {vm, set_info, vm_id(), attr_list()} |
        {vm, list, Requirements::[matcher()], Full::boolean()} |
        {vm, list} |
        {vm, nic, add, Vm::vm_id(), IPRange::iprange_id()} |
        {vm, nic, remove, Vm::vm_id(), IPRange::iprange_id()} |
        {vm, nic, primary, Vm::vm_id(), MAC::binary()}.

-type sniffle_hypervisor_message() ::
        {hypervisor, register, Hypervisor::hypervisor_id(),
         Host::binary(),
         Port::inet:port_number()} |
        {hypervisor, unregister, Hypervisor::hypervisor_id()} |
        {hypervisor, get, Hypervisor::hypervisor_id()} |
        {hypervisor, service, Hypervisor::hypervisor_id(),
         Action::enable|disable|clear|refresh|restart, Service::binary()} |
        {hypervisor, set_resource, Hypervisor::hypervisor_id(), attr_list()} |
        {hypervisor, set_characteristic,
         Hypervisor::hypervisor_id(), attr_list()} |
        {hypervisor, set_metadata, Hypervisor::hypervisor_id(), attr_list()} |
        {hypervisor, set_pool, Hypervisor::hypervisor_id(), attr_list()} |
        {hypervisor, set_service, Hypervisor::hypervisor_id(), attr_list()} |
        {hypervisor, alias, Hypervisor::hypervisor_id(), binary()} |
        {hypervisor, etherstubs, Hypervisor::hypervisor_id(), list()} |
        {hypervisor, host, Hypervisor::hypervisor_id(), binary()} |
        {hypervisor, networks, Hypervisor::hypervisor_id(), list()} |
        {hypervisor, path, Hypervisor::hypervisor_id(), list()} |
        {hypervisor, port, Hypervisor::hypervisor_id(), inet:port_number()} |
        {hypervisor, sysinfo, Hypervisor::hypervisor_id(), list()} |
        {hypervisor, uuid, Hypervisor::hypervisor_id(), binary()} |
        {hypervisor, version, Hypervisor::hypervisor_id(), binary()} |
        {hypervisor, virtualisation, Hypervisor::hypervisor_id(), list()} |
        {hypervisor, list} |
        {hypervisor, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_dataset_message() ::
        {dataset, create, Dataset::dataset_id()} |
        {dataset, delete, Dataset::dataset_id()} |
        {dataset, import, URL::dataset_id()} |
        {dataset, get, Dataset::dataset_id()} |
        {dataset, list} |
        {dataset, status, Dataset::dataset_id(), binary()} |
        {dataset, imported,
         Dataset::dataset_id(), float() | non_neg_integer()} |
        {dataset, description, Dataset::dataset_id(), binary()} |
        {dataset, disk_driver, Dataset::dataset_id(), binary()} |
        {dataset, homepage, Dataset::dataset_id(), binary()} |
        {dataset, image_size, Dataset::dataset_id(), non_neg_integer()} |
        {dataset, name, Dataset::dataset_id(), binary()} |
        {dataset, networks, Dataset::dataset_id(), list()} |
        {dataset, nic_driver, Dataset::dataset_id(), binary()} |
        {dataset, os, Dataset::dataset_id(), binary()} |
        {dataset, type, Dataset::dataset_id(), kvm | zone} |
        {dataset, users, Dataset::dataset_id(), list()} |
        {dataset, version, Dataset::dataset_id(), binary()} |
        {dataset, set_metadata, Dataset::dataset_id(), attr_list()} |
        {dataset, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_network_message() ::
        {network, create, binary()} |
        {network, delete, network_id()} |
        {network, add_iprange, network_id(), iprange_id()} |
        {network, remove_iprange, network_id(), iprange_id()} |
        {network, get, network_id()} |
        {network, uuid, network_id(), binary()} |
        {network, name, network_id(), binary()} |
        {network, set_metadata, iprange_id(), attr_list()} |
        {network, list} |
        {network, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_iprange_message() ::
        {iprange, create,
         Iprange::binary(),
         Network::integer(),
         Gateway::integer(),
         Netmask::integer(),
         First::integer(),
         Last::integer(),
         Tag::binary(),
         VLan::pos_integer()} |
        {iprange, delete, Iprange::iprange_id()} |
        {iprange, get, Iprange::iprange_id()} |
        {iprange, release, Iprange::iprange_id(), Ip::integer()} |
        {iprange, claim, Iprange::iprange_id()} |
        {iprange, list} |
        {iprange, name, iprange_id(), binary()} |
        {iprange, uuid, iprange_id(), binary()} |
        {iprange, network, iprange_id(), non_neg_integer()} |
        {iprange, netmask, iprange_id(), non_neg_integer()} |
        {iprange, gateway, iprange_id(), non_neg_integer()} |
        {iprange, set_metadata, iprange_id(), attr_list()} |
        {iprange, tag, iprange_id(), non_neg_integer()} |
        {iprange, vlan, iprange_id(), non_neg_integer()} |

        {iprange, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_package_message() ::
        {package, create, PackageName::binary()} |
        {package, delete, package_id()} |
        {package, get, package_id()} |
        {package, set_metadata, package_id(), attr_list()} |
        {package, blocksize, package_id(), pos_integer()} |
        {package, compression, package_id(), binary()} |
        {package, cpu_cap, package_id(), pos_integer()} |
        {package, cpu_shares, package_id(), pos_integer()} |
        {package, max_swap, package_id(), pos_integer()} |
        {package, name, package_id(), binary()} |
        {package, quota, package_id(), pos_integer()} |
        {package, ram, package_id(), pos_integer()} |
        {package, uuid, package_id(), binary()} |
        {package, zfs_io_priority, package_id(), pos_integer()} |
        {package, remove_requirement, package_id(), term()} |
        {package, add_requirement, package_id(), term()} |
        {package, list} |
        {package, list, Requirements::[matcher()], Full::boolean()}.


-type sniffle_grouping_message() ::
        {grouping, add, GroupingName::binary(), grouping_type()} |
        {grouping, delete, grouping_id()} |
        {grouping, get, grouping_id()} |
        {grouping, element, add | remove,
         grouping_id(), Element::grouping_id()| vm_id()} |
        {grouping, grouping, add | remove,
         grouping_id(), Parent::grouping_id()} |
        {grouping, metadata, set, grouping_id(), attr_list()} |
        {grouping, config, set, grouping_id(), attr_list()} |
        {grouping, list} |
        {grouping, list, Requirements::[matcher()], Full::boolean()}.

%%%===================================================================
%%%  Snarl
%%%===================================================================

-type snarl_message() ::
        version |
        {cloud, status} |
        {token, delete, Realm::realm(), Token::token()} |
        {user, auth, Realm::realm(), UserName::binary(), Pass::binary()} |
        {user, token, Realm::realm(), user_id()} |
        {user, auth,
         Realm::realm(), UserName::binary(), Pass::binary(), basic | binary()} |
        {user, allowed,
         Realm::realm(), User::user_token_id(), Permission::permission()}.

-type snarl_user_message() ::
        {user, list, realm()} |
        {user, list, realm(), Requirements::[matcher()], Full::boolean()} |
        {user, get, realm(), user_id()} |
        {user, get, realm(), token()} |
        {user, lookup, realm(), UserName::binary()} |
        {user, cache, realm(), token()} |
        {user, cache, realm(), user_id()} |
        {user, add, realm(), UserName::binary()} |
        {user, add, realm(), Creator::user_id(), UserName::binary()} |
        {user, delete, realm(), user_id()} |
        {user, passwd, realm(), user_id(), Pass::binary()} |
        {user, join, realm(), user_id(), Role::role_id()} |
        {user, leave, realm(), user_id(), Role::role_id()} |
        {user, grant, realm(), user_id(), Permission::permission()} |
        {user, revoke, realm(), user_id(), Permission::permission()} |
        {user, revoke_prefix, realm(), user_id(), Permission::permission()} |
        {user, keys, find, realm(), KeyID::binary()} |
        {user, keys, add, realm(), user_id(), KeyID::binary(), Key::binary()} |
        {user, keys, revoke, realm(), user_id(), KeyID::binary()} |
        {user, keys, get, realm(), user_id()} |
        {user, yubikeys, add, realm(), user_id(), binary()} |
        {user, yubikeys, remove, realm(), user_id(), binary()} |
        {user, yubikeys, get, realm(), user_id()} |
        {user, set_metadata, realm(), user_id(), Attrs::attr_list()} |
        {user, org, join, realm(), user_id(), Org::org_id()} |
        {user, org, leave, realm(), user_id(), Org::role_id()} |
        {user, org, active, realm(), user_id()} |
        {user, org, select, realm(), user_id(), Org::org_id()}.

-type snarl_role_message() ::
        {role, list, realm()} |
        {role, list, realm(), Requirements::[matcher()], Full::boolean()} |
        {role, get, realm(), role_id()} |
        {role, add, realm(), RoleName::binary()} |
        {role, delete, realm(), role_id()} |
        {role, set_metadata, realm(), role_id(), Attrs::attr_list()} |
        {role, grant, realm(), role_id(), Permission::permission()} |
        {role, revoke_prefix, realm(), role_id(), Permission::permission()} |
        {role, revoke, realm(), role_id(), Permission::permission()}.

-type snarl_org_message() ::
        {org, list, realm()} |
        {org, list, realm(), Requirements::[matcher()], Full::boolean()} |
        {org, get, realm(), org_id()} |
        {org, add, realm(), OrgName::binary()} |
        {org, delete, realm(), org_id()} |
        {org, set_metadata, realm(), org_id(), Attrs::attr_list()} |
        {org, trigger, add, realm(), org_id(), Trigger::trigger()} |
        {org, trigger, remove, realm(), org_id(), Trigger::trigger()} |
        {org, trigger, execute, realm(), org_id(), Trigger::trigger(),
         Payload::term()} |
        {org, resource_action, realm(), org_id(), Resource::binary(),
         Timestamp::pos_integer(), Action::atom(), Opts::proplists:proplist()}.

-type acc_action() :: create | update | destroy.

-type snarl_acc_message() ::
        {accounting, acc_action(),
         realm(), org_id(), uuid(), pos_integer(), term()} |
        {accounting, get, realm(), org_id()} |
        {accounting, get, realm(), org_id(), uuid()} |
        {accounting, get, realm(), org_id(),
         Start :: pos_integer(), End :: pos_integer()}.

-type scope_list() :: [binary()].
-type scope_map() :: #{
                 name => binary(),
                 desc => binary(),
                 default => boolean(),
                 permissions => list()
                }.
-type uri() :: binary().
-type snarl_oauth_message() ::
        {oauth2, scope, realm()} |
        {oauth2, scope, realm(), ScopeName ::binary()} |
        {oauth2, authorize_password,
         realm(), user_id(), scope_list()} |
        {oauth2, authorize_password,
         realm(), user_id(), client_id(), scope_list()} |
        {oauth2, authorize_password,
         realm(), user_id(), client_id(), uri(), scope_list()} |
        {oauth2, authorize_client_credentials,
         realm(), client_id(), scope_list()} |
        {oauth2, authorize_code_grant,
         realm(), client_id(), Code::binary(), uri()} |
        {oauth2, authorize_code_request,
         realm(), user_id(), client_id(), uri(), scope_list()} |
        {oauth2, issue_code, realm(), Auth::term()} |
        {oauth2, issue_token, realm(), Auth::term()} |
        {oauth2, issue_token_and_refresh, realm(), Auth::term()} |
        {oauth2, verify_access_token, realm(), Token::binary()} |
        {oauth2, verify_access_code, realm(), AccessCode::binary()} |
        {oauth2, verify_access_code,
         realm(), AccessCode::binary(), client_id()} |
        {oauth2, refresh_access_token,
         realm(), client_id(), RefreshToken::binary(), scope_list()}.



-type write_fsm_reply() ::
        not_found | ok | {error, timeout} | {ok, term()}.

-type read_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.

-type coverage_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.

-type smartos_fw_targets() ::
        {vm, UUID :: vm_id() | all} |
        {ip, IP :: integer()} |
        {subnet, Base :: integer(), Mask :: integer()} |
        {tag, Tag :: binary(), Val :: binary() | integer()} |
        {tag, Tag :: binary()} |
        any.

-type icmp_type() ::
        {icmp, Type :: non_neg_integer()} |
        {icmp, Type :: non_neg_integer(), Code :: non_neg_integer()}.

-type fw_action() ::
        allow |
        block.

-type smartos_fw_rule() ::
        {fw_action(), [smartos_fw_targets()], [smartos_fw_targets()],
         tcp | udp, [integer()]} |
        {fw_action(), [smartos_fw_targets()], [smartos_fw_targets()],
         icmp, [icmp_type()]}.

-type fw_direction() ::
        inbound |
        outbound.

-type fw_target() ::
        all |
        {ip, IP :: pos_integer()} |
        {subnet, Network :: pos_integer(), Mask ::integer()} |
        {vm, UUID :: vm_id()} |
        {cluster, UUID :: grouping_id()} |
        {stack, UUID :: grouping_id()} |
        {network, UUID :: network_id()}.

-type fw_filter() ::
        {tcp | udp, [integer()]} |
        {icmp, [icmp_type()]}.

-type fw_iface() ::
        {nic, Interface :: binary()} |
        {network, UUID :: network_id()} |
        all.

-type firewall_rule() ::
        {fw_action(), fw_direction(), fw_target(), fw_filter()} |
        {fw_action(), fw_iface(), fw_direction(), fw_target(), fw_filter()}.
