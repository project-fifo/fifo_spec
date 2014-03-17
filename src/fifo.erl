-module(fifo).

-export_type([config_list/0,
              attr_list/0,
              key/0,
              keys/0,
              object/0,
              config/0,
              package/0,
              dataset/0,
              dataset_id/0,
              dtrace_id/0,
              package_id/0,
              iprange_id/0,
              network/0,
              network_id/0,
              vm_config/0,
              vm_type/0,
              vm_state/0,
              vm_state_atom/0,
              log/0,
              value/0,
              matcher/0,
              uuid/0]).

-export_type([user/0,
              user_id/0,
              group/0,
              group_id/0,
              org/0,
              org_id/0,
              user_token_id/0,
              token/0,
              trigger/0,
              event/0
             ]).

-export_type([resource_id/0,
              reservation/0,
              resource/0,
              resource_claim/0]).

-export_type([permission/0,
              comparer/0,
              number_comparer/0,
              set_comparer/0,
              element_comparer/0,
              permission_comparer/0]).

-export_type([sniffle_message/0,
              howl_message/0,
              chunter_message/0,
              snarl_message/0]).

-export_type([hypervisor/0,
              hypervisor_id/0]).

-export_type([vm/0,
              vm_id/0]).

-export_type([write_fsm_reply/0,
              read_fsm_reply/0,
              coverage_fsm_reply/0]).


-type key()::binary()|integer().

-type keys()::key()|[key()].

-type value()::binary()|number()|object()|jsxarray()|null|true|false.

-type object()::[{binary(), value()}].

-type jsxarray()::[value()].

-type hypervisor_id() :: binary().
-type vm_id() :: uuid().
-type user_id() :: uuid().
-type org_id() :: uuid().
-type user_token_id() :: user_id() | {token, Token::token()}.
-type group_id() :: uuid().
-type resource_id() :: uuid().
-type dataset_id() :: uuid().
-type package_id() :: uuid().
-type iprange_id() :: uuid().
-type network_id() :: uuid().
-type dtrace_id() :: uuid().

-type trigger() :: term().

-type log() :: {{integer(), integer(), integer()}, term()}.

-type group() :: object().

-type user() :: object().

-type org() :: object().

-type network() :: object().

-type token() :: uuid().

-type event() :: atom().

-type resource() ::
        {resource,
         Name :: resource_id(),
         Granted :: number(),
         Claims :: [resource_claim()],
         Reservations :: [reservation()]}.

-type reservation() ::
        {Claim :: resource_claim(),
         Timeout :: integer()}.

-type resource_claim() ::
        {resource_claim,
         Id :: uuid(),
         Ammount :: number()}.

-type vm() ::
        {vm,
         UUID :: vm_id(),
         Alias :: binary(),
         Hypervisor :: hypervisor_id(),
         Log :: [log()],
         Attributes :: dict()
        }.

-type permission() ::
        [binary() | '_' | '...'].

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
        {matcher_type(), permission_comparer(), Key::permission_key(), [permission()]}.

-type config_list() :: [{Key::binary(),
                         Value::value()}].

-type attr_list() :: [{Key::keys(),
                       Value::value()}].

-type hypervisor() :: object().

-type vm_config() :: object().

-type config() :: object().

-type package() :: object().

-type dataset() :: object().

-type uuid() :: <<_:288>>.

-type vm_type() :: kvm | zone.

-type vm_state_atom() ::
        booting |
        shutting_down |
        running |
        stopped.

-type vm_state() ::
        binary().

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
        {machines, start, UUID::vm_id()} |
        {machines, start, UUID::vm_id(), Image::binary()} |
        {machines, stop, UUID::vm_id()} |
        {machines, stop, force, UUID::vm_id()} |
        {machines, reboot, UUID::vm_id()} |
        {machines, reboot, force, UUID::vm_id()} |
        {machines, snapshot, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, delete, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, rollback, UUID::vm_id(), SnapID::uuid()} |
        {machines, snapshot, store, UUID::vm_id(), SnapID::uuid(), Img::dataset_id()} |
        {machines, create,
         UUID::vm_id(),
         PSpec::package(),
         DSpec::dataset(),
         Config::config()} |
        {machines, delete, UUID::vm_id()} |
        {machines, update,
         UUID::vm_id(),
         PSpec::package(),
         Config::config()}.

%%%===================================================================
%%%  Sniffle
%%%===================================================================

-type sniffle_message() ::
        ping |
        version |
        {cloud, status} |
        sniffle_dtrace_message() |
        sniffle_vm_messages() |
        sniffle_hypervisor_messages() |
        sniffle_dataset_message() |
        sniffle_image_message() |
        sniffle_iprange_message() |
        sniffle_network_message() |
        sniffle_package_message().

-type sniffle_dtrace_message() ::
        {dtrace, add, Name::binary(), Script::string()} |
        {dtrace, delete, ID::dtrace_id()} |
        {dtrace, get, ID::dtrace_id()} |
        {dtrace, list} |
        {dtrace, list, Requreiments::[matcher()], Full::boolean()} |
        {dtrace, attribute, set, ID::dtrace_id(),
         Attribute::keys(), Value::value() | delete} |
        {dtrace, attribute, set, ID::dtrace_id(), Attributes::attr_list()} |
        {dtrace, run, ID::dtrace_id(), Servers::[hypervisor()]}.

-type sniffle_vm_messages() ::
        {vm, log, Vm::vm_id(), Log::term()} |
        {vm, register, Vm::vm_id(), Hypervisor::binary()} |
        {vm, snapshot, Vm::vm_id(), Comment::binary()} |
        {vm, snapshot, delete, Vm::vm_id(), UUID::uuid()} |
        {vm, snapshot, rollback, Vm::vm_id(), UUID::uuid()} |
        {vm, snapshot, promote, Vm::vm_id(),
         SnapUUID::uuid(), Dataset::config()} |
        {vm, create, Package::binary(), Dataset::binary(), Config::config()} |
        {vm, update, Vm::vm_id(),
         Package::package_id() | undefined, Config::config()} |
        {vm, unregister, Vm::vm_id()} |
        {vm, get, Vm::vm_id()} |
        {vm, start, Vm::vm_id()} |
        {vm, delete, Vm::vm_id()} |
        {vm, stop, Vm::vm_id()} |
        {vm, reboot, Vm::vm_id()} |
        {vm, stop, force, Vm::vm_id()} |
        {vm, reboot, force, Vm::vm_id()} |
        {vm, set, Vm::vm_id(), Attribute::keys(), Value::value() | delete} |
        {vm, set, Vm::vm_id(), Attributes::attr_list()} |
        {vm, list} |
        {vm, list, Requirements::[matcher()], Full::boolean()} |
        {vm, nic, add, Vm::vm_id(), IPRange::iprange_id()} |
        {vm, nic, remove ,Vm::vm_id(), IPRange::iprange_id()} |
        {vm, nic, primary ,Vm::vm_id(), MAC::binary()}.

-type sniffle_hypervisor_messages() ::
        {hypervisor, register, Hypervisor::hypervisor(),
         Host::binary(),
         Port::inet:port_number()} |
        {hypervisor, unregister, Hypervisor::hypervisor()} |
        {hypervisor, get, Hypervisor::hypervisor()} |
        {hypervisor, set, Hypervisor::hypervisor(), Resource::binary(), Value::value() | delete} |
        {hypervisor, set, Hypervisor::hypervisor(), Resources::config_list()} |
        {hypervisor, list} |
        {hypervisor, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_dataset_message() ::
        {dataset, create, Dataset::binary()} |
        {dataset, delete, Dataset::dataset_id()} |
        {dataset, import, URL::binary()} |
        {dataset, get, Dataset::binary()} |
        {dataset, set, Dataset::binary(), Attribute::keys(), Value::value() | delete} |
        {dataset, set, Dataset::binary(), Attributes::attr_list()} |
        {dataset, list} |
        {dataset, list, Requirements::[matcher()], Full::boolean()}.

-type sniffle_image_message() ::
        {img, create, Img::dataset_id(), Idx::integer(), Data::binary()} |
        {img, delete, Img::dataset_id()} |
        {img, delete, Img::dataset_id(), Idx::integer()} |
        {img, get, Img::dataset_id(), Idx::integer()} |
        {img, list} |
        {img, list, Img::dataset_id()}.

-type sniffle_network_message() ::
        {network, create, Network::binary()} |
        {network, delete, Network::network_id()} |
        {network, add_iprange, Network::network_id(), Iprange::iprange_id()} |
        {network, remove_iprange, Network::network_id(), Iprange::iprange_id()} |
        {network, get, Network::binary()} |
        {network, set, Network::binary(), Attribute::keys(), Value::value() | delete} |
        {network, set, Network::binary(), Attributes::attr_list()} |
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
        {iprange, list, Requirements::[matcher()], Full::boolean()} |
        {iprange, set, Iprange::iprange_id(), Attribute::keys(), Value::value() | delete} |
        {iprange, set, Iprange::iprange_id(), Attributes::attr_list()}.

-type sniffle_package_message() ::
        {package, create, PackageName::binary()} |
        {package, delete, Package::package_id()} |
        {package, get, Package::package_id()} |
        {package, set, Package::package_id(), Attribute::keys(), Value::value() | delete} |
        {package, set, Package::package_id(), Attributes::attr_list()} |
        {package, list} |
        {package, list, Requirements::[matcher()], Full::boolean()}.

%%%===================================================================
%%%  Snarl
%%%===================================================================

-type snarl_message() ::
        version |
        {cloud, status} |
        {token, delete, Token::token()} |
        {user, list} |
        {user, list, Requirements::[matcher()], Full::boolean()} |
        {user, get, User::user_token_id()} |
        {user, set, User::user_id(), Attribute::keys(), Value::value() | delete} |
        {user, set, User::user_id(), Attributes::attr_list()} |
        {user, lookup, UserName::binary()} |
        {user, cache, User::user_token_id()} |
        {user, add, UserName::binary()} |
        {user, add, Creator::user_id(), UserName::binary()} |
        {user, auth, UserName::binary(), Pass::binary()} |
        {user, auth, UserName::binary(), Pass::binary(), basic | binary()} |
        {user, allowed, User::user_token_id(), Permission::permission()} |
        {user, delete, User::user_id()} |
        {user, passwd, User::user_id(), Pass::binary()} |
        {user, join, User::user_id(), Group::group_id()} |
        {user, leave, User::user_id(), Group::group_id()} |
        {user, grant, User::user_id(), Permission::permission()} |
        {user, revoke, User::user_id(), Permission::permission()} |
        {user, revoke_prefix, User::user_id(), Permission::permission()} |
        {user, set_resource, User::user_id(), Resource::binary(), Value::value()} |
        {user, claim_resource, User::user_id(), Resource::binary(), Ammount::number()} |
        {user, free_resource, User::user_id(), Resource::binary(), ID::uuid()} |
        {user, resource_stat, User::user_id()} |
        {user, keys, find, KeyID::binary()} |
        {user, keys, add, User::user_id(), KeyID::binary(), Key::binary()} |
        {user, keys, revoke, User::user_id(), KeyID::binary()} |
        {user, keys, get, User::user_id()} |
        {user, yubikeys, add, User::user_id(), binary()} |
        {user, yubikeys, remove, User::user_id(),binary()} |
        {user, yubikeys, get, User::user_id()} |
        {user, org, join, User::user_id(), Org::org_id()} |
        {user, org, leave, User::user_id(), Org::group_id()} |
        {user, org, active, User::user_id()} |
        {user, org, select, User::user_id(), Org::org_id()} |
        {group, list} |
        {group, list, Requirements::[matcher()], Full::boolean(), Full::boolean()} |
        {group, get, Group::group_id()} |
        {group, set, Group::group_id(), Attribute::keys(), Value::value() | delete} |
        {group, set, Group::group_id(), Attributes::attr_list()} |
        {group, add, GroupName::binary()} |
        {group, delete, Group::group_id()} |
        {group, grant, Group::group_id(), Permission::permission()} |
        {group, revoke_prefix, Group::group_id(), Permission::permission()} |
        {group, revoke, Group::group_id(), Permission::permission()} |
        {org, list} |
        {org, list, Requirements::[matcher()], Full::boolean()} |
        {org, get, Org::org_id()} |
        {org, set, Org::org_id(), Attribute::keys(), Value::value() | delete} |
        {org, set, Org::org_id(), Attributes::attr_list()} |
        {org, add, OrgName::binary()} |
        {org, delete, Org::org_id()} |
        {org, trigger, add, Org::org_id(), Trigger::trigger()} |
        {org, trigger, remove, Org::org_id(), Trigger::trigger()} |
        {org, trigger, execute, Org::org_id(), Trigger::trigger(), Payload::term()}.

-type write_fsm_reply() ::
        not_found | ok | {error, timeout} | {ok, term()}.

-type read_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.

-type coverage_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.
