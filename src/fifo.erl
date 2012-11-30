-module(fifo).


-export_type([config_list/0,
	      config/0,
	      package/0,
	      dataset/0,
	      uuid/0]).

-type config_list() :: [{Key::binary(), Value::term()}].

-type config() :: config_list().

-type package() :: config_list().

-type dataset() :: config_list().

-type uuid() :: binary().


