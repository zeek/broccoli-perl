package Broccoli::Connection::Type;

#dummy packages for blessing types


package Broccoli::Connection;

use 5.12.0;
use strict;
use warnings;

use Class::Accessor;
use Carp::Assert;
use Data::Dumper;
use Exporter;
use Scalar::Util qw/blessed/;

use base qw(Exporter Class::Accessor);
our $VERSION = 0.01;


our %EXPORT_TAGS = ('types' => [qw/count btime record current_time/] );

Exporter::export_ok_tags('types');

#has 'destination' => (is => 'rw', isa => 'Str', required => 1);
#has 'broclass' => (is => 'rw', isa => 'Str', required => 0, default => "");

#has 'broconn' => (is => 'rw');

__PACKAGE__->mk_accessors(qw/destination broconn/);

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

=head1 NAME

Broccoli::Connection - connect to broccoli

=head1 SYNOPSIS

	# import Broccoli and all types
	use Broccoli::Connection qw/:types/;

	# connect to bro
	my $b = Broccoli::Connection->new(
		{
			destination => "localhost:47758"
		});

	# send events
	$b->send("ping", seq++);

	# define event handlers
	$b->event("pong", sub {
		my $seq = shift;
		say "Received pong with number $seq";
	});

	# register event handlers with broccoli
	$b->registerEvents() 

=head1 FUNCTIONS

=over 4

=item B<new>

	my $bro = Broccoli::Connection->new(\%Parameters);

Create a new bro connection. Currently there is only one parameter named
destination that has to be set.

=cut

sub new {
	my $self = Class::Accessor::new(@_);
	
	assert(defined($self->destination));

	$self->broconn(setup($self->destination));
	
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
	assert(defined($name));
	my $coderef = shift;
	assert(defined($coderef));
	
	my %call = (
		event => $name,
		callback => $coderef,
		self => $self,
	);

	say "registering event $name";
	addCallback($self->broconn, $name, \%call);
}


sub dispatchCallback {
	my $param = shift;
	assert(defined($param));
		
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
	assert(defined($arg));

	return bless {
		type => "BRO_TYPE_COUNT",
		value => $arg
	}, 'Broccoli::Connection::Type';
}

=item B<btime>

Set the type of the value to time

=cut

sub btime {
	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );

	my $arg = shift;
	assert(defined($arg));

	return bless {
		type => "BRO_TYPE_TIME",
		value => $arg
	}, 'Broccoli::Connection::Type';
}

#sub record {
#	shift if ( defined $_[0] && defined(blessed($_[0])) && blessed($_[0]) eq __PACKAGE__ );
#	
#	my $arg = shift;
#	assert(defined($arg));
#
#	return bless $arg, 'Broccoli::Connection::RECORD';
#}

=item B<current_time>

	my $currtime = current_time();

Return the current timestamp according to bro.

=cut

sub current_time {
	return bro_util_current_time();
}


sub parseArgument {
	my $arg = shift;
	my $type;
	
	assert (defined($arg));
	
	if ( defined(blessed($arg)) &&  blessed($arg) eq 'Broccoli::Connection::Type') {
		assert(defined($$arg{"type"}));
		assert(defined($$arg{"value"}));
		$type = $$arg{"type"};
		$arg = $$arg{"value"};		

	} elsif (ref($arg) eq 'HASH') { 
		my $record = bro_record_new();
		
		while (my ($key, $value) = each($arg) ) {
			my ($type, $val) = parseArgument($value);
			#say "adding type $type to record";
			my $res = bro_record_add_val_short($record, $key, $type, $val);
			assert($res != 0);
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

	die if ( !defined($type) || !defined($BROTYPES{$type}) );
	
	my $typenum = $BROTYPES{$type};
	
	return ($typenum, objToVal($arg, $typenum));
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

=back

=cut

sub send {
	my $self = shift;
	my $name = shift;
	
	
	my $ev = bro_event_new($name);
	for my $arg (@_) {
		my ($typenum, $value) = parseArgument($arg);
		
		bro_event_add_val_short($ev, $typenum, $value);

	}

	bro_event_send($self->broconn, $ev);
	bro_event_free($ev);
	bro_conn_process_input($self->broconn);
}

use Inline C => Config =>
        VERSION => '0.01',
        NAME => 'Broccoli::Connection',
	LIBS => $ENV{LDDFLAGS}.' -lbroccoli',
#	MYEXTLIB => '-lbroccoli',
	CCFLAGS => $ENV{CCFLAGS},
#       MYEXTLIB => '/n/shokuji/db/bernhard/broinstall/lib/libbroccoli.so',
#	CCFLAGS => "-I/n/shokuji/db/bernhard/broinstall/include",
#	TYPEMAPS => "/n/shokuji/db/bernhard/Broccoli-Connection/lib/Broccoli/btypemap",
	AUTO_INCLUDE => '#include "broccoli.h"',
	ENABLE => "AUTOWRAP";

use Inline C => <<'END_OF_C_CODE';
#include <dlfcn.h>

BroRecord* testingonly () {
	//BroEvent* be = bro_event_new("test");
	BroRecord* br = bro_record_new();
	
	//bro_event_add_val_short(be, 18, br);
	return br;
}

SV* parseArg(BroEvArg arg) {
	switch ( arg.arg_type ) {
		case BRO_TYPE_BOOL:
		case BRO_TYPE_INT: {
			int64_t* val = (int64_t *) arg.arg_data;

			int v = *val;

			return (newSViv(v));
			break;
		}
		
		case BRO_TYPE_COUNT:
		case BRO_TYPE_COUNTER: {
			uint64_t* val = (uint64_t *) arg.arg_data;

			return (newSVuv(*val));
			break;
		}
		
		case BRO_TYPE_DOUBLE:
		case BRO_TYPE_TIME:
		case BRO_TYPE_INTERVAL: {
			double* val = (double *) arg.arg_data;
			double v = *val;			
			
			return (newSVnv(v));
			break;
		} 
		
		case BRO_TYPE_RECORD: { // oh, yummie, a record
			HV* h = newHV();
			BroRecord *rec = arg.arg_data;
			int i = 0;
			int *type = (int*) malloc(sizeof(int));
			const char *name;
			while ( (name = bro_record_get_nth_name(rec, i) ) != NULL ) {
				*type = BRO_TYPE_UNKNOWN;
				void * value = bro_record_get_nth_val(rec, i, type);
				//printf("Adding field: %s at position %d with type %d\n", name, i, *type);
				if ( value == NULL ) {
					croak("Internal error - undefined value. Record name %s", name);
				}
				
				BroEvArg dummyev;
				dummyev.arg_data = value;
				dummyev.arg_type = *type;
				
				hv_store(h, name, strlen(name), parseArg(dummyev), 0); 
				i++;
			}
			return newRV_noinc((SV*) h);
			break;
		}

		default: {	
			croak("unimplemented type %d", arg.arg_type);
		}
	}
}

void callbackfunction(BroConn *bc, void* user_data, BroEvMeta *meta) {

	//char * event_name = (char*) user_data;
	if ( user_data == NULL ) {
		croak("null userdata");
	}

	SV* s = (SV*) user_data;

	// ok, handle the meta arguments...
	int numargs = meta->ev_numargs;
	int i; 

	//printf("%d args", numargs);
	
	BroEvArg* args = meta->ev_args;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(s);
	
	for ( i = 0; i < numargs; i++ ) {
		XPUSHs(sv_2mortal(parseArg(args[i])));
	}
	
	PUTBACK;
	call_pv("dispatchCallback", G_DISCARD);
	
	FREETMPS;
	LEAVE;

	//croak("Callback called -- event name was %s", event_name);
}

void addCallback(BroConn *bc, const char* event_name, SV *user_data) {
	//croak("Registering %s", event_name);
	//char *eventnamecopy = (char*) malloc(strlen(event_name)+1);
	//memcpy(eventnamecopy, event_name, strlen(event_name)+1);
	
	SV* e = SvREFCNT_inc(user_data);

	bro_event_registry_add_compact(bc, event_name, callbackfunction, (void*) e);
}

void * stringToPtr(const char *string) {
	char * out = malloc(strlen(string)+1);
	memcpy(out, string, strlen(string)+1);
	return (void*)&out; 
	//return (void*) &string;
}

BroConn *setup(char * destination) {
	dlopen("libbroccoli.so", RTLD_NOW);
	bro_init(NULL);
	BroConn *bc = bro_conn_new_str(destination, BRO_CFLAG_NONE);
	
	if ( !bc ) {
		croak("Could not get connection handle");
	}
	
	if ( !bro_conn_connect(bc)) {
		croak("Could not connect to bro");
	}

	return bc;

}


void * objToVal(SV* obj, int type) {
	switch (type) {
		case BRO_TYPE_BOOL:
		case BRO_TYPE_INT: {
			int64_t* tmp = (int64_t *)malloc(sizeof(int64_t));
			*tmp = SvIV(obj);
			return (void*) tmp;
			break;
		}

		case BRO_TYPE_COUNT:
		case BRO_TYPE_COUNTER: {
			uint64_t* tmp = (uint64_t *)malloc(sizeof(uint64_t));
			*tmp = SvUV(obj);
			return (void*) tmp;
			break;
		}

		case BRO_TYPE_DOUBLE:
		case BRO_TYPE_TIME:
		case BRO_TYPE_INTERVAL: {
			double* tmp = (double *)malloc(sizeof(double));
			*tmp = SvNV(obj);
			return (void*) tmp;
			break;
		}

		case BRO_TYPE_STRING: {
			BroString* str = (BroString*) malloc(sizeof(BroString));
			bro_string_init(str);
			STRLEN len;
			char* tmp;
			tmp = SvPV(obj, len);
			
			if ( !bro_string_set_data(str, tmp, len)) {
				carp("Problem");
			} 

			return (void*) str;
			break;
		}
		
		default: {
			croak("unimplemented type");
			return NULL;
		}
	}
}

int bro_event_add_val_short(BroEvent *be, int type, const void *val) {
	return bro_event_add_val(be, type, NULL, val);
}

int bro_record_add_val_short(BroRecord *rec, const char *name, int type, const void *val) {
	return bro_record_add_val(rec, name, type, NULL, val);
}


int            bro_init(const BroCtx *ctx);
BroConn       *bro_conn_new_str(const char *hostname, int flags);
void           bro_conn_set_class(BroConn *bc, const char *classname);
int            bro_conn_connect(BroConn *bc);
int            bro_conn_process_input(BroConn *bc);
int            bro_event_queue_length(BroConn *bc);
BroEvent      *bro_event_new(const char *event_name);
void           bro_event_free(BroEvent *be);
int            bro_event_add_val(BroEvent *be, int type, const char *type_name, const void *val);
int            bro_event_send(BroConn *bc, BroEvent *be);
void           bro_event_registry_add_compact(BroConn *bc, const char *event_name, BroCompactEventFunc func, void *user_data);
double         bro_util_current_time();
BroRecord     *bro_record_new();
int            bro_conn_get_fd(BroConn *bc);
void           bro_event_registry_request(BroConn *bc);


END_OF_C_CODE

1;
