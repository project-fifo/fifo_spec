-module(fifo).


-export_type([config_list/0,
              config/0,
              package/0,
              dataset/0,
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
              chunter_message/0,
              smarl_message/0]).

-export_type([hypervisor/0,
              hypervisor_id/0]).
-export_type([vm/0,
              vm_id/0]).

-type hypervisor_id() :: binary().
-type vm_id() :: binary().
-type user_id() :: binary().
-type group_id() :: binary().
-type resource_id() :: binary().

-type log() :: {{integer(), integer(), integer()}, term()}.

-type group() ::
        {group,
         Name :: group_id(),
         Permissions :: [permission()],
         Users :: [user_id()]}.

-type user() ::
        {user,
         Name :: user_id(),
         Passwd :: binary(),
         Permissions :: [permission()],
         Resources :: [resource()],
         Groups :: [group_id()]}.


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

-type matcher() ::
        {matcher_type(), number_comparer(), Key::binary(), number()} |
        {matcher_type(), set_comparer(), Key::binary(), [term()]} |
        {matcher_type(), element_comparer(), Key::binary(), term()} |
        {matcher_type(), permission_comparer(), Key::binary(), permission()}.



-type value() :: number() |
                 boolean() |
                 binary() |
                 [value()] |
                 config_list().

-type hypervisor() ::
        binary().

-type config_list() :: [{Key::binary(),
                         Value::value()}].

-type vm_config() :: config_list().

-type config() :: config_list().

-type package() :: config_list().

-type dataset() :: config_list().

-type uuid() :: binary().

-type vm_type() :: kvm | zone.

-type chunter_message() ::
        ping |
        {machines, start, UUID::uuid()} |
        {machines, start, UUID::uuid(), Image::binary()} |
        {machines, stop, UUID::uuid()} |
        {machines, reboot, UUID::uuid()} |
        {machines, create,
         UUID::uuid(),
         PSpec::package(),
         DSpec::dataset(),
         Config::config()} |
        {machines, delete, UUID::uuid()}.

-type vm_state_atom() ::
        booting |
        shutting_down |
        running |
        stopped.

-type vm_state() ::
        binary().


-type sniffle_vm_messages() ::
        {vm, register, Vm::uuid(), Hypervisor::binary()} |
        {vm, create, Package::binary(), Dataset::binary(), Config::config()} |
        {vm, unregister, Vm::uuid()} |
        {vm, get, Vm::uuid()} |
        {vm, log, Vm::uuid(), Log::term()} |
        {vm, attribute, get, Vm::uuid()} |
        {vm, start, Vm::uuid()} |
        {vm, delete, Vm::uuid()} |
        {vm, stop, Vm::uuid()} |
        {vm, reboot, Vm::uuid()} |
        {vm, attribute, get, Vm::uuid(), Attribute::binary()} |
        {vm, attribute, set, Vm::uuid(), Attribute::binary(), Value::value()} |
        {vm, attribute, set, Vm::uuid(), Attributes::config_list()} |
        {vm, list} |
        {vm, list, Requirements::[matcher()]}.

-type sniffle_hypervisor_messages() ::
        {hypervisor, register, Hypervisor::hypervisor(),
         Host::inet:ip_address() | inet:hostname(),
         Port::inet:port_number()} |
        {hypervisor, unregister, Hypervisor::hypervisor()} |
        {hypervisor, resource, get, Hypervisor::hypervisor(), Resource::binary()} |
        {hypervisor, resource, get, Hypervisor::hypervisor()} |
        {hypervisor, resource, set, Hypervisor::hypervisor(), Resource::binary(), Value::value()} |
        {hypervisor, resource, set, Hypervisor::hypervisor(), Resources::config_list()} |
        {hypervisor, list} |
        {hypervisor, list, Requirements::[matcher()]}.


-type sniffle_dataset_message() ::
        {dataset, create, Dataset::binary()} |
        {dataset, delete, Dataset::binary()} |
        {dataset, attribute, get, Dataset::binary()} |
        {dataset, attribute, get, Dataset::binary(), Attribute::binary()} |
        {dataset, attribute, set, Dataset::binary(), Attribute::binary(), Value::value()} |
        {dataset, attribute, set, Dataset::binary(), Attributes::config_list()} |
        {dataset, list} |
        {dataset, list, Requirements::[matcher()]}.

-type sniffle_iprange_message() ::
        {iprange, create,
         Iprange::binary(),
         Network::integer(),
         Gateway::integer(),
         Netmask::integer(),
         First::integer(),
         Last::integer(),
         Tag::binary()} |
        {iprange, delete, Iprange::binary()} |
        {iprange, get, Iprange::binary()} |
        {iprange, release, Iprange::binary(), Ip::integer()} |
        {iprange, claim, Iprange::binary()} |
        {iprange, list} |
        {iprange, list, Requirements::[matcher()]}.

-type sniffle_package_message() ::
        {package, create, Package::binary()} |
        {package, delete, Package::binary()} |
        {package, get, Package::binary()} |
        {package, attribute, get, Package::binary()} |
        {package, attribute, get, Package::binary(), Attribute::binary()} |
        {package, attribute, set, Package::binary(), Attribute::binary(), Value::value()} |
        {package, attribute, set, Package::binary(), Attributes::config_list()} |
        {package, list} |
        {package, list, Requirements::[matcher()]}.

-type sniffle_message() ::
        ping |
        version |
        {cloud, status} |
        sniffle_vm_messages() |
        sniffle_hypervisor_messages() |
        sniffle_dataset_message() |
        sniffle_iprange_message() |
        sniffle_package_message().


-type smarl_message() ::
        version |
        {user, list} |
        {user, get,
         User::{token, Token::uuid()} | binary()} |
        {user, cache,
         User::{token, Token::uuid()} | binary()} |
        {user, add, User::binary()} |
        {user, auth, User::binary(), Pass::binary()} |
        {user, allowed, {token, Token::binary()}, Permission::permission()} |
        {user, allowed, User::binary(), Permission::permission()} |
        {user, delete, User::binary()} |
        {user, passwd, User::binary(), Pass::binary()} |
        {user, join, User::binary(), Group::group_id()} |
        {user, leave, User::binary(), Group::group_id()} |
        {user, grant, User::binary(), Permission::permission()} |
        {user, revoke, User::binary(), Permission::permission()} |
        {user, set_resource, User::binary(), Resource::binary(), Value::value()} |
        {user, claim_resource, User::binary(), Resource::binary(), Ammount::number()} |
        {user, free_resource, User::binary(), Resource::binary(), ID::uuid()} |
        {user, resource_stat, User::binary()} |
        {group, list} |
        {group, get, Group::group_id()} |
        {group, add, Group::group_id()} |
        {group, delete, Group::group_id()} |
        {group, grant, Group::group_id(), Permission::permission()} |
        {group, revoke, Group::group_id(), Permission::permission()}.
