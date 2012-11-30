-module(fifo).


-export_type([config_list/0,
	      config/0,
	      package/0,
	      dataset/0,
	      vm_config/0,
	      vm_type/0,
	      chunter_message/0,
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

-type chunter_message() ::
	ping |
	{machine, start, UUID::uuid()} |
	{machine, start, UUID::uuid(), Image::binary()} |
	{machine, stop, UUID::uuid()} |
	{machine, reboot, UUID::uuid()} |
	{machines, create,
	 UUID::uuid(),
	 PSpec::package(),
	 DSpec::dataset(),
	 Config::config()} |
	{machine, delete, UUID::uuid()}.

-type vm_states() :: binary().
