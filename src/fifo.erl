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
              vm_config/0,
              vm_type/0,
              vm_state/0,
              vm_state_atom/0,
              log/0,
              value/0,
              matcher/0,
              uuid/0]).


-export_type([user/0,
              group_id/0,
              user_id/0,
              group/0
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
-type group_id() :: uuid().
-type resource_id() :: uuid().
-type dataset_id() :: uuid().
-type package_id() :: uuid().
-type iprange_id() :: uuid().
-type dtrace_id() :: uuid().

-type log() :: {{integer(), integer(), integer()}, term()}.

-type group() :: object().

-type user() :: object().


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

-type uuid() :: binary().

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
        sniffle_package_message().

-type sniffle_dtrace_message() ::
        {dtrace, add, Name::binary(), Script::string()} |
        {dtrace, delete, ID::uuid()} |
        {dtrace, get, ID::uuid()} |
        {dtrace, list} |
        {dtrace, list, Requreiments::[matcher()]} |
        {dtrace, attribute, set, ID::uuid(), Attribute::keys(), Value::value() | delete} |
        {dtrace, attribute, set, ID::uuid(), Attributes::attr_list()} |
        {dtrace, run, ID::uuid(), Servers::[hypervisor()]}.

-type sniffle_vm_messages() ::
        {vm, log, Vm::uuid(), Log::term()} |
        {vm, register, Vm::uuid(), Hypervisor::binary()} |
        {vm, snapshot, Vm::uuid(), Comment::binary()} |
        {vm, snapshot, delete, Vm::uuid(), UUID::uuid()} |
        {vm, snapshot, rollback, Vm::uuid(), UUID::uuid()} |
        {vm, create, Package::binary(), Dataset::binary(), Config::config()} |
        {vm, update, Vm::uuid(), Package::uuid(), Config::config()} |
        {vm, unregister, Vm::uuid()} |
        {vm, get, Vm::uuid()} |
        {vm, start, Vm::uuid()} |
        {vm, delete, Vm::uuid()} |
        {vm, stop, Vm::uuid()} |
        {vm, reboot, Vm::uuid()} |
        {vm, stop, force, Vm::uuid()} |
        {vm, reboot, force, Vm::uuid()} |
        {vm, set, Vm::uuid(), Attribute::keys(), Value::value() | delete} |
        {vm, set, Vm::uuid(), Attributes::attr_list()} |
        {vm, list} |
        {vm, list, Requirements::[matcher()]}.

-type sniffle_hypervisor_messages() ::
        {hypervisor, register, Hypervisor::hypervisor(),
         Host::binary(),
         Port::inet:port_number()} |
        {hypervisor, unregister, Hypervisor::hypervisor()} |
        {hypervisor, get, Hypervisor::hypervisor()} |
        {hypervisor, set, Hypervisor::hypervisor(), Resource::binary(), Value::value() | delete} |
        {hypervisor, set, Hypervisor::hypervisor(), Resources::config_list()} |
        {hypervisor, list} |
        {hypervisor, list, Requirements::[matcher()]}.

-type sniffle_dataset_message() ::
        {dataset, create, Dataset::binary()} |
        {dataset, delete, Dataset::binary()} |
        {dataset, import, URL::binary()} |
        {dataset, get, Dataset::binary()} |
        {dataset, set, Dataset::binary(), Attribute::keys(), Value::value() | delete} |
        {dataset, set, Dataset::binary(), Attributes::attr_list()} |
        {dataset, list} |
        {dataset, list, Requirements::[matcher()]}.

-type sniffle_image_message() ::
        {img, create, Img::uuid(), Idx::pos_integer(), Data::binary()} |
        {img, delete, Img::uuid()} |
        {img, delete, Img::uuid(), Idx::pos_integer()} |
        {img, get, Img::uuid(), Idx::pos_integer()} |
        {img, list} |
        {img, list, Img::uuid()}.

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
        {iprange, delete, Iprange::binary()} |
        {iprange, get, Iprange::binary()} |
        {iprange, release, Iprange::binary(), Ip::integer()} |
        {iprange, claim, Iprange::binary()} |
        {iprange, list} |
        {iprange, list, Requirements::[matcher()]} |
        {iprange, set, Iprange::binary(), Attribute::keys(), Value::value() | delete} |
        {iprange, set, Iprange::binary(), Attributes::attr_list()}.

-type sniffle_package_message() ::
        {package, create, PackageName::binary()} |
        {package, delete, Package::uuid()} |
        {package, get, Package::uuid()} |
        {package, set, Package::uuid(), Attribute::keys(), Value::value() | delete} |
        {package, set, Package::uuid(), Attributes::attr_list()} |
        {package, list} |
        {package, list, Requirements::[matcher()]}.

%%%===================================================================
%%%  Snarl
%%%===================================================================

-type snarl_message() ::
        version |
        {token, delete, Token::uuid()} |
        {user, list} |
        {user, get,
         User::{token, Token::uuid()} | uuid()} |
        {user, set, User::uuid(), Attribute::keys(), Value::value() | delete} |
        {user, set, User::uuid(), Attributes::attr_list()} |
        {user, lookup, UserName::binary()} |
        {user, cache,
         User::{token, Token::uuid()} | uuid()} |
        {user, add, UserName::binary()} |
        {user, auth, UserName::binary(), Pass::binary()} |
        {user, allowed, User::{token, Token::uuid()}|uuid(), Permission::permission()} |
        {user, delete, User::uuid()} |
        {user, passwd, User::uuid(), Pass::binary()} |
        {user, join, User::uuid(), Group::group_id()} |
        {user, leave, User::uuid(), Group::group_id()} |
        {user, grant, User::uuid(), Permission::permission()} |
        {user, revoke, User::uuid(), Permission::permission()} |
        {user, revoke_all, User::uuid(), Permission::permission()} |
        {user, set_resource, User::uuid(), Resource::binary(), Value::value()} |
        {user, claim_resource, User::uuid(), Resource::binary(), Ammount::number()} |
        {user, free_resource, User::uuid(), Resource::binary(), ID::uuid()} |
        {user, resource_stat, User::uuid()} |
        {group, list} |
        {group, get, Group::group_id()} |
        {group, set, Group::group_id(), Attribute::keys(), Value::value() | delete} |
        {group, set, Group::group_id(), Attributes::attr_list()} |
        {group, add, Group::group_id()} |
        {group, delete, Group::group_id()} |
        {group, grant, Group::group_id(), Permission::permission()} |
        {group, revoke, Group::group_id(), Permission::permission()}.

-type write_fsm_reply() ::
        not_found | ok | {error, timeout} | {ok, term()}.

-type read_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.

-type coverage_fsm_reply() ::
        not_found | {error, timeout} | {ok, term()}.
