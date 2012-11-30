-module(fifo).


-export_type([config_list/0,
	      config/0,
	      package/0,
	      dataset/0,
	      vm_config/0,
	      vm_type/0,
	      uuid/0]).


-type value() :: number() |
		 boolean() |
		 binary() |
		 [value()] |
		 config_list().

-type config_list() :: [{Key::binary(),
			 Value::value()}].

-type vm_config() :: config_list().

-type config() :: config_list().

-type package() :: config_list().

-type dataset() :: config_list().

-type uuid() :: binary().

-type vm_type() :: kvm | zone.

