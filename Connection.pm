package Broccoli::Connection::Type;

#dummy packages for blessing types

package Broccoli::Connection;

use 5.10.1;
use strict;
use warnings;

use Exporter;
use Scalar::Util qw/blessed/;

use base qw(Exporter);
our $VERSION = 0.01;

XSLoader::load "Broccoli::Connection", $VERSION;

our %EXPORT_TAGS = ('types' => [qw/count btime current_time port interval double addr subnet bool/] );

Exporter::export_ok_tags('types');

my %BROTYPES = ( 
BRO_TYPE_UNKNOWN =>          0,
BRO_TYPE_BOOL =>             1,
BRO_TYPE_INT =>              2,
BRO_TYPE_COUNT =>            3,
BRO_TYPE_COUNTER =>          4,
BRO_TYPE_DOUBLE =>           5,
BRO_TYPE_TIME =>             6,
BRO_TYPE_INTERVAL =>         7,
BRO_TYPE_STRING =>           8,
BRO_TYPE_PATTERN =>          9,
BRO_TYPE_ENUM =>            10,
BRO_TYPE_TIMER =>           11,
BRO_TYPE_PORT =>            12,
BRO_TYPE_IPADDR =>          13,
BRO_TYPE_SUBNET =>          14,
BRO_TYPE_ANY =>             15,
BRO_TYPE_TABLE =>           16,
BRO_TYPE_UNION =>           17,
BRO_TYPE_RECORD =>          18,
BRO_TYPE_LIST =>            19,
BRO_TYPE_FUNC =>            20,
BRO_TYPE_FILE =>            21,
BRO_TYPE_VECTOR =>          22,
BRO_TYPE_ERROR =>           23,
BRO_TYPE_PACKET =>          24, # /* CAUTION -- not defined in Bro! */
BRO_TYPE_SET =>             25, # /* ----------- (ditto) ---------- */
BRO_TYPE_MAX =>             26,
);

my %protocols = (
icmp => 1,
igmp => 2,
ipip => 4,
tcp => 6,
udp => 17,
ipv6 => 41,
routing => 43,
fragment => 44,
rsvp => 46,
gre => 47,
esp => 50,
ag => 51,
icmpv6 => 58,
none => 59,
dstopts => 60,
mtp => 92,
encap => 98,
pim => 103,
comp => 108,
sctp => 132,
raw => 255,
);

=head1 NAME

Broccoli::Connection - connect to broccoli

=head1 SYNOPSIS

	# import Broccoli and all types
	use Broccoli::Connection qw/:types/;

	# connect to bro
	my $b = Broccoli::Connection->new(
			destination => "localhost:47758",
			quess_types => 1,
		);

	# send events
	my $seq = 0;
	$b->send("ping", $seq++);

	# send records
	$b->send("recordtest", {
		intvalue => 1,
		stringvalue => "hi",
	});
	
	# send records of records
	$b->send("RecordOfRecordTest", { 
		first => { intvalue => 1 }, 
		second => { addr => "192.168.17.1" }
	};

	# specify types
	$b->send("counttest", count(5));

	# define event handlers
	$b->event("pong", sub {
		my $seq = shift;
		say "Received pong with number $seq";
	});

	# register event handlers with broccoli
	$b->registerEvents();

=head1 FUNCTIONS

=over 4

=item B<new>

	my $bro = Broccoli::Connection->new(%Parameters);

Create a new bro connection. 

Possible parameters: destination and guess_types.

Destination is the bro connection information. If guess_types is set, the connection class will automatically detect port, addr and subnet arguments.

So, you can write

	$b->send("1.2.5.8", "77/udp");
	
instead of
	
	$b->send(addr("1.2.5.8"), port("77/udp"));

=cut


sub destination {
	my ($self, $arg) = @_;
	
	if ( defined($arg) ) {
		$$self{"destination"} = $arg;
	}

	return $$self{"destination"};
}

sub broconn {
	my ($self, $arg) = @_;
	
	if ( defined($arg) ) {
		$$self{"broconn"} = $arg;
	}

	return $$self{"broconn"};
}

sub guess_types {
	my ($self, $arg) = @_;
	
	if ( defined($arg) ) {
		$$self{"guess_types"} = $arg;
	}

	return $$self{"guess_types"};
}

sub new {
	my $class = shift;
	my $self = { @_ };
	bless $self, $class;
	
	die("assertion") unless(defined($self->destination));

	$self->broconn(setup($self->destination));
	if ( !defined($self->guess_types) ) {
		$self->guess_types(0);
	}
	
	return $self;
}

=item B<event>

	event(NAME, FUNCTIONREFERENCE);

Register the event NAME and call the given function reverence when
the event is sent by bro.

=cut

sub event {
	my $self = shift;

	my $name = shift;
	die("assertion") unless(defined($name));
	my $coderef = shift;
	die("assertion") unless(defined($coderef));
	
	my %call = (
		event => $name,
		callback => $coderef,
		self => $self,
	);

	#say "registering event $name";
	addCallback($self->broconn, $name, \%call);
}


sub dispatchCallback {
	my $param = shift;
	die("assertion") unless(defined($param));
		
	&{$$param{"callback"}}(@_);
}

=item B<registerEvents()>

	$bro->registerEvents();

Register the event handlers with bro. Has to be called once to receive evevents.

=cut

sub registerEvents() {
	my $self = shift;
	bro_event_registry_request($self->broconn);
}

=item B<count>

	$bro->send("ping", count(12));

or
	
	$bro->send("ping", $bro->count(12));

if the types have not been imported into the namespace.

Set the type of the value to count

=cut

sub count {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	return bless {
		type => "BRO_TYPE_COUNT",
		value => $arg
	}, 'Broccoli::Connection::Type';
}

=item B<count>

Set the type of the value to bool

=cut

sub bool {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	return bless {
		type => "BRO_TYPE_BOOL",
		value => $arg
	}, 'Broccoli::Connection::Type';
}



=item B<btime>

Set the type of the value to time

=cut

sub btime {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	return bless {
		type => "BRO_TYPE_TIME",
		value => $arg
	}, 'Broccoli::Connection::Type';
}

=item B<port>

	port("125/tcp");

Set the type of the value to port.

=cut

sub port {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	die unless($arg =~ m#(\d+)\/(\w+)#);
	
	my $port = $1;
	my $proto = $2;

	die("assertion") unless (defined($protocols{lc($proto)}));

	return bless {
		type => "BRO_TYPE_PORT",
		value => [$port, $protocols{$proto}]
	}, 'Broccoli::Connection::Type';
}

=item B<interval>

Set the type of the value to interval

=cut

sub interval {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	return bless {
		type => "BRO_TYPE_INTERVAL",
		value => $arg
	}, 'Broccoli::Connection::Type';

}

=item B<double>

Set the type of the value to interval

=cut

sub double {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	return bless {
		type => "BRO_TYPE_DOUBLE",
		value => $arg
	}, 'Broccoli::Connection::Type';

}

=item B<addr>

Set the type of the value to addr

=cut

sub addr {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));
	
	#die("invalid addr format: $arg") unless($arg =~ m#(\d+)\/(\w+)#);
	
	return bless {
		type => "BRO_TYPE_IPADDR",
		value => $arg
	}, 'Broccoli::Connection::Type';

}

=item B<subnet>

Set the type of the value to subnet

=cut

sub subnet {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	die("assertion") unless(defined($arg));

	die("invalid addr format: $arg") unless($arg =~ m#(^[\d\.]+)\/(\w+)$#);
	
	my $addr = $1;
	my $mask = $2;
	
	return bless {
		type => "BRO_TYPE_SUBNET",
		value => [ $addr, $mask]
	}, 'Broccoli::Connection::Type';

}


=item B<current_time>

	my $currtime = current_time();

Return the current timestamp according to bro.

=cut

sub current_time {
	return bro_util_current_time();
}

sub parseArgument {
	my $self = shift;
	my $arg = shift;
	my $type;

	if ( defined($arg) && !defined(blessed($arg)) && !ref($arg) && $self->guess_types ) {
		# ok, type guessing time :)
		# say "guessing what $arg is";
		if ( $arg =~ m#^\d+/(tcp|udp)$# ) {
			# say "port";
			$arg = port($arg);
		} elsif ( $arg =~ m#^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$# ) {
			# say "addr";
			$arg = addr($arg);
		} elsif ( $arg =~ m#^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$# ) {
			# say "subnet";
			$arg = subnet($arg);
		}
	}
              
	
	if ( !defined($arg) ) {
		# well, this is perfectly ok. 
		$type = "BRO_TYPE_UNKNOWN";
	} else { 
		
		if ( defined(blessed($arg)) &&  blessed($arg) eq 'Broccoli::Connection::Type') {
			die("assertion") unless(defined($$arg{"type"}));
			die("assertion") unless(defined($$arg{"value"}));
			$type = $$arg{"type"};
			$arg = $$arg{"value"};		

		} elsif (ref($arg) eq 'HASH') { 
			my $record = bro_record_new();
			#say "creating record";
		
			while (my ($key, $value) = each($arg) ) {
				my ($type, $val) = $self->parseArgument($value);
				#say "adding type $type to record";
				my $res = bro_record_add_val_short($record, $key, $type, $val) if ($type != 0);  # Ignore BRO_TYPE_UNKNOWN
				if ( $type != 0 ) {
					die("assertion") unless($res != 0);
				}
			}
		
			return (18, $record);
		} else {

			given( $arg ) {
				when( /^\d+\z/ )
					{ continue }
				when( /^-?\d+\z/ )
					{ continue }
				when( /^[+-]?\d+\z/ )
					{ $type = "BRO_TYPE_INT" }
				when( /^-?(?:\d+\.?|\.\d)\d*\z/ )
					{ continue }
				when( /^[+-]?(?=\.?\d)\d*\.?\d*(?:e[+-]?\d+)?\z/i)
					{ $type = "BRO_TYPE_FLOAT" }
				default { $type = "BRO_TYPE_STRING" }
			}	
		}
	}

	die if ( !defined($type) || !defined($BROTYPES{$type}) );
	
	my $typenum = $BROTYPES{$type};
	
	return ($typenum, 
	objToVal($arg, $typenum));
}

=item B<send>

	$bro->send(EVENT, PARAM1, PARAM2, ...)

Send the event EVENT with parameters PARAM1, ...
The type of the parameters is either given via the appropriate functions like count or determined automatically by inspecting the variable contents.

Records can be sent by defining a hashref, e.g.:

	$bro->send("test", { 
		a => 1,
		b => count(2).
	});


=cut

sub send {
	my $self = shift;
	my $name = shift;
	
	
	my $ev = bro_event_new($name);
	for (@_) {
		my ($typenum, $value) = $self->parseArgument($_);
		bro_event_add_val_short($ev, $typenum, $value);

	}

	bro_event_send($self->broconn, $ev);
			
	bro_event_free($ev);
	bro_conn_process_input($self->broconn);
}

=item B<process>

Process pending input events

=back

=cut

sub process {
	my $self = shift;
	bro_conn_process_input($self->broconn);
}



# use Inline C => Config =>
#         VERSION => '0.01',
#         NAME => 'Broccoli::Connection',
# 	LIBS => $ENV{LDDFLAGS}.' -lbroccoli',
# #	MYEXTLIB => '-lbroccoli',
# 	CCFLAGS => $ENV{CCFLAGS},
# #       MYEXTLIB => '/n/shokuji/db/bernhard/broinstall/lib/libbroccoli.so',
# #	CCFLAGS => "-I/n/shokuji/db/bernhard/broinstall/include",
# #	TYPEMAPS => "/n/shokuji/db/bernhard/Broccoli-Connection/lib/Broccoli/btypemap",
# 	AUTO_INCLUDE => '#include "broccoli.h"',
# 	ENABLE => "AUTOWRAP";
# 
# use Inline C => <<'END_OF_C_CODE';
# #include <sys/socket.h>
# #include <netinet/in.h>
# #include <arpa/inet.h>
# 
# SV* parseArg(BroEvArg arg) {
# 	switch ( arg.arg_type ) {
# 		case BRO_TYPE_BOOL:
# 		case BRO_TYPE_INT: {
# 			int64_t* val = (int64_t *) arg.arg_data;
# 
# 			int v = *val;
# 
# 			return (newSViv(v));
# 			break;
# 		}
# 		
# 		case BRO_TYPE_COUNT:
# 		case BRO_TYPE_COUNTER: {
# 			uint64_t* val = (uint64_t *) arg.arg_data;
# 
# 			return (newSVuv(*val));
# 			break;
# 		}
# 		
# 		case BRO_TYPE_DOUBLE:
# 		case BRO_TYPE_TIME:
# 		case BRO_TYPE_INTERVAL: {
# 			double* val = (double *) arg.arg_data;
# 			double v = *val;			
# 			
# 			return (newSVnv(v));
# 			break;
# 		} 
# 		
# 		case BRO_TYPE_STRING: {
# 			BroString *str = (BroString*) arg.arg_data;
# 			
# 			SV* val = newSVpvn(str->str_val, str->str_len);
# 			return val;
# 			break;
# 		}
# 		
# 		case BRO_TYPE_PORT: {
# 			BroPort *port = (BroPort*) arg.arg_data;
# 			
# 			SV* out = newSVpvf("%u/%d", port->port_num, port->port_proto);
# 			return out;
# 			break;
# 		}
# 		
# 		case BRO_TYPE_SUBNET: {
# 			BroSubnet *net = (BroSubnet*) arg.arg_data;
# 			
# 			struct in_addr address;
# 			address.s_addr = net->sn_net;
# 			char* str = inet_ntoa(address);
# 
# 			SV* out = newSVpvf("%s/%d", str, net->sn_width);
# 			return out;
# 			break;
# 		}
# 
# 		
# 		case BRO_TYPE_IPADDR: {
# 			struct in_addr address;
# 			address.s_addr = *((unsigned long*) arg.arg_data);
# 			
# 			char* str = inet_ntoa(address);
# 			SV* out = newSVpv(str, 0);
# 			return out;
# 			break;
# 		}
# 		
# 		case BRO_TYPE_RECORD: { // oh, yummie, a record
# 			HV* h = newHV();
# 			BroRecord *rec = arg.arg_data;
# 			int i = 0;
# 			int *type = (int*) malloc(sizeof(int));
# 			const char *name;
# 			while ( (name = bro_record_get_nth_name(rec, i) ) != NULL ) {
# 				*type = BRO_TYPE_UNKNOWN;
# 				void * value = bro_record_get_nth_val(rec, i, type);
# 				//printf("Adding field: %s at position %d with type %d\n", name, i, *type);
# 				if ( value == NULL ) {
# 					croak("Internal error - undefined value. Record name %s", name);
# 				}
# 				
# 				BroEvArg dummyev;
# 				dummyev.arg_data = value;
# 				dummyev.arg_type = *type;
# 				
# 				hv_store(h, name, strlen(name), parseArg(dummyev), 0); 
# 				i++;
# 			}
# 			return newRV_noinc((SV*) h);
# 			break;
# 		}
# 
# 		default: {	
# 			croak("unimplemented type %d in parsearg", arg.arg_type);
# 		}
# 	}
# }
# 
# void callbackfunction(BroConn *bc, void* user_data, BroEvMeta *meta) {
# 
# 	//char * event_name = (char*) user_data;
# 	if ( user_data == NULL ) {
# 		croak("null userdata");
# 	}
# 
# 	SV* s = (SV*) user_data;
# 
# 	// ok, handle the meta arguments...
# 	int numargs = meta->ev_numargs;
# 	int i; 
# 
# 	//printf("%d args", numargs);
# 	
# 	BroEvArg* args = meta->ev_args;
# 
# 	dSP;
# 	ENTER;
# 	SAVETMPS;
# 	PUSHMARK(SP);
# 	XPUSHs(s);
# 	
# 	for ( i = 0; i < numargs; i++ ) {
# 		XPUSHs(sv_2mortal(parseArg(args[i])));
# 	}
# 	
# 	PUTBACK;
# 	call_pv("dispatchCallback", G_DISCARD);
# 	
# 	FREETMPS;
# 	LEAVE;
# 
# 	//croak("Callback called -- event name was %s", event_name);
# }
# 
# void addCallback(BroConn *bc, const char* event_name, SV *user_data) {
# 	//croak("Registering %s", event_name);
# 	//char *eventnamecopy = (char*) malloc(strlen(event_name)+1);
# 	//memcpy(eventnamecopy, event_name, strlen(event_name)+1);
# 	
# 	SV* e = SvREFCNT_inc(user_data);
# 
# 	bro_event_registry_add_compact(bc, event_name, callbackfunction, (void*) e);
# }
# 
# void * stringToPtr(const char *string) {
# 	char * out = malloc(strlen(string)+1);
# 	memcpy(out, string, strlen(string)+1);
# 	return (void*)out; 
# 	//return (void*) &string;
# }
# 
# BroConn *setup(char * destination) {
# 	bro_init(NULL);
# 	BroConn *bc = bro_conn_new_str(destination, BRO_CFLAG_NONE);
# 	
# 	if ( !bc ) {
# 		croak("Could not get connection handle");
# 	}
# 	
# 	if ( !bro_conn_connect(bc)) {
# 		croak("Could not connect to bro");
# 	}
# 
# 	return bc;
# 
# }
# 
# 
# void * objToVal(SV* obj, int type) {
# 	switch (type) {
# 		case BRO_TYPE_BOOL:
# 		case BRO_TYPE_INT: {
# 			int64_t* tmp = (int64_t *)malloc(sizeof(int64_t));
# 			*tmp = SvIV(obj);
# 			return (void*) tmp;
# 			break;
# 		}
# 
# 		case BRO_TYPE_PORT: {
# 			// obj is arrayref.
# 			if ( !SvRV(obj) ) {
# 				croak("Expected reference");
# 			}
# 			if ( !( SvTYPE(SvRV(obj)) == SVt_PVAV ) ) {
# 				croak("Expected array reference");
# 			}
# 			
# 			AV* array = (AV*) SvRV(obj);
# 			
# 			if ( av_len(array) != 1 ) { // index of last element
# 				croak("Expected pair, len is: %d", av_len(array));
# 			}
# 			
# 			SV* theport = av_shift(array);
# 			SV* theprotocol = av_shift(array);
# 			
# 			BroPort* port = (BroPort *)malloc(sizeof(BroPort));
# 			port->port_num = SvUV(theport);
# 			port->port_proto = SvIV(theprotocol);
# 			return (void*) port;
# 			break;
# 			
# 		}
# 		
# 		case BRO_TYPE_SUBNET: {
# 			// obj is arrayref.
# 			if ( !SvRV(obj) ) {
# 				croak("Expected reference");
# 			}
# 			if ( !( SvTYPE(SvRV(obj)) == SVt_PVAV ) ) {
# 				croak("Expected array reference");
# 			}
# 			
# 			AV* array = (AV*) SvRV(obj);
# 			
# 			if ( av_len(array) != 1 ) { // index of last element
# 				croak("Expected pair, len is: %d", av_len(array));
# 			}
# 			
# 			SV* thenet = av_shift(array);
# 			SV* thewidth = av_shift(array);
# 			const char* netchar = SvPV_nolen(thenet);
# 			
# 			struct in_addr addr;
# 			int res = inet_aton(netchar, &addr);
# 			if ( res == 0 ) {
# 				croak("not an address");
# 			}
# 
# 			
# 			BroSubnet* net = (BroSubnet *)malloc(sizeof(BroSubnet));
# 			//printf("the net is %u\n", SvUV(thenet));
# 			net->sn_net = addr.s_addr;
# 			net->sn_width = SvUV(thewidth);
# 			return (void*) net;
# 			break;
# 			
# 		}
# 
# 
# 		case BRO_TYPE_COUNT:
# 		case BRO_TYPE_COUNTER: {
# 			uint64_t* tmp = (uint64_t *)malloc(sizeof(uint64_t));
# 			*tmp = SvUV(obj);
# 			return (void*) tmp;
# 			break;
# 		}
# 
# 		case BRO_TYPE_DOUBLE:
# 		case BRO_TYPE_TIME:
# 		case BRO_TYPE_INTERVAL: {
# 			double* tmp = (double *)malloc(sizeof(double));
# 			*tmp = SvNV(obj);
# 			return (void*) tmp;
# 			break;
# 		}
# 				
# 		case BRO_TYPE_IPADDR: {
# 			const char* tmp;
# 			tmp = SvPV_nolen(obj);
# 			//printf("address: %s\n", tmp);
# 
# 			struct in_addr addr;
# 			int res = inet_aton(tmp, &addr);
# 			if ( res == 0 ) {
# 				croak("not an address");
# 			}
# 			
# 			uint32_t* out = (uint32_t*)malloc(sizeof(uint32_t));
# 			*out = addr.s_addr;
# 			
# 			return (void*) out;
# 			break;
# 		}
# 
# 		case BRO_TYPE_STRING: {
# 			BroString* str = (BroString*) malloc(sizeof(BroString));
# 			bro_string_init(str);
# 			STRLEN len;
# 			char* tmp;
# 			tmp = SvPV(obj, len);
# 			
# 			if ( !bro_string_set_data(str, tmp, len)) {
# 				carp("Problem");
# 			} 
# 
# 			return (void*) str;
# 			break;
# 		}
# 		
# 		case BRO_TYPE_UNKNOWN: {
# 			// test if car is undef.
# 			if ( SvOK(obj) ) {
# 				carp("Undefined object is defined?");
# 			}
# 			
# 			return NULL;
# 		}
# 		
# 		default: {
# 			croak("unimplemented type %d in objtoval", type);
# 			return NULL;
# 		}
# 	}
# }
# 
# int bro_event_add_val_short(BroEvent *be, int type, const void *val) {
# 	return bro_event_add_val(be, type, NULL, val);
# }
# 
# int bro_record_add_val_short(BroRecord *rec, const char *name, int type, const void *val) {
# 	return bro_record_add_val(rec, name, type, NULL, val);
# }
# 
# 
# int            bro_init(const BroCtx *ctx);
# BroConn       *bro_conn_new_str(const char *hostname, int flags);
# void           bro_conn_set_class(BroConn *bc, const char *classname);
# int            bro_conn_connect(BroConn *bc);
# int            bro_conn_process_input(BroConn *bc);
# int            bro_event_queue_length(BroConn *bc);
# BroEvent      *bro_event_new(const char *event_name);
# void           bro_event_free(BroEvent *be);
# int            bro_event_add_val(BroEvent *be, int type, const char *type_name, const void *val);
# int            bro_event_send(BroConn *bc, BroEvent *be);
# void           bro_event_registry_add_compact(BroConn *bc, const char *event_name, BroCompactEventFunc func, void *user_data);
# double         bro_util_current_time();
# BroRecord     *bro_record_new();
# int            bro_conn_get_fd(BroConn *bc);
# void           bro_event_registry_request(BroConn *bc);
# 
# 
# END_OF_C_CODE

1;
