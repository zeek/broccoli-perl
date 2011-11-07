#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "broccoli.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
		
		case BRO_TYPE_STRING: {
			BroString *str = (BroString*) arg.arg_data;
			
			SV* val = newSVpvn(str->str_val, str->str_len);
			return val;
			break;
		}
		
		case BRO_TYPE_PORT: {
			BroPort *port = (BroPort*) arg.arg_data;
			
			SV* out = newSVpvf("%llu/%d", port->port_num, port->port_proto);
			return out;
			break;
		}
		
		case BRO_TYPE_SUBNET: {
			BroSubnet *net = (BroSubnet*) arg.arg_data;
			
			struct in_addr address;
			address.s_addr = net->sn_net;
			char* str = inet_ntoa(address);

			SV* out = newSVpvf("%s/%d", str, net->sn_width);
			return out;
			break;
		}

		
		case BRO_TYPE_IPADDR: {
			struct in_addr address;
			address.s_addr = *((unsigned long*) arg.arg_data);
			
			char* str = inet_ntoa(address);
			SV* out = newSVpv(str, 0);
			return out;
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
			croak("unimplemented type %d in parsearg", arg.arg_type);
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
	return (void*)out; 
	//return (void*) &string;
}

BroConn *setup(char * destination) {
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

		case BRO_TYPE_PORT: {
			// obj is arrayref.
			if ( !SvRV(obj) ) {
				croak("Expected reference");
			}
			if ( !( SvTYPE(SvRV(obj)) == SVt_PVAV ) ) {
				croak("Expected array reference");
			}
			
			AV* array = (AV*) SvRV(obj);
			
			if ( av_len(array) != 1 ) { // index of last element
				croak("Expected pair, len is: %d", av_len(array));
			}
			
			SV* theport = av_shift(array);
			SV* theprotocol = av_shift(array);
			
			BroPort* port = (BroPort *)malloc(sizeof(BroPort));
			port->port_num = SvUV(theport);
			port->port_proto = SvIV(theprotocol);
			return (void*) port;
			break;
			
		}
		
		case BRO_TYPE_SUBNET: {
			// obj is arrayref.
			if ( !SvRV(obj) ) {
				croak("Expected reference");
			}
			if ( !( SvTYPE(SvRV(obj)) == SVt_PVAV ) ) {
				croak("Expected array reference");
			}
			
			AV* array = (AV*) SvRV(obj);
			
			if ( av_len(array) != 1 ) { // index of last element
				croak("Expected pair, len is: %d", av_len(array));
			}
			
			SV* thenet = av_shift(array);
			SV* thewidth = av_shift(array);
			const char* netchar = SvPV_nolen(thenet);
			
			struct in_addr addr;
			int res = inet_aton(netchar, &addr);
			if ( res == 0 ) {
				croak("not an address");
			}

			
			BroSubnet* net = (BroSubnet *)malloc(sizeof(BroSubnet));
			//printf("the net is %u\n", SvUV(thenet));
			net->sn_net = addr.s_addr;
			net->sn_width = SvUV(thewidth);
			return (void*) net;
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
				
		case BRO_TYPE_IPADDR: {
			const char* tmp;
			tmp = SvPV_nolen(obj);
			//printf("address: %s\n", tmp);

			struct in_addr addr;
			int res = inet_aton(tmp, &addr);
			if ( res == 0 ) {
				croak("not an address");
			}
			
			uint32_t* out = (uint32_t*)malloc(sizeof(uint32_t));
			*out = addr.s_addr;
			
			return (void*) out;
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
		
		case BRO_TYPE_UNKNOWN: {
			// test if car is undef.
			if ( SvOK(obj) ) {
				carp("Undefined object is defined?");
			}
			
			return NULL;
		}
		
		default: {
			croak("unimplemented type %d in objtoval", type);
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



MODULE = Broccoli::Connection	PACKAGE = Broccoli::Connection	

PROTOTYPES: DISABLE


void
callbackfunction (bc, user_data, meta)
	BroConn *	bc
	void *	user_data
	BroEvMeta *	meta
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	callbackfunction(bc, user_data, meta);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

void
addCallback (bc, event_name, user_data)
	BroConn *	bc
	const char *	event_name
	SV *	user_data
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	addCallback(bc, event_name, user_data);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

void *
stringToPtr (string)
	const char *	string

BroConn *
setup (destination)
	char *	destination

void *
objToVal (obj, type)
	SV *	obj
	int	type

int
bro_event_add_val_short (be, type, val)
	BroEvent *	be
	int	type
	const void *	val

int
bro_record_add_val_short (rec, name, type, val)
	BroRecord *	rec
	const char *	name
	int	type
	const void *	val

BroConn *
bro_conn_new_str (hostname, flags)
	const char *	hostname
	int	flags

void
bro_conn_set_class (bc, classname)
	BroConn *	bc
	const char *	classname
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	bro_conn_set_class(bc, classname);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

int
bro_conn_connect (bc)
	BroConn *	bc

int
bro_conn_process_input (bc)
	BroConn *	bc

int
bro_event_queue_length (bc)
	BroConn *	bc

BroEvent *
bro_event_new (event_name)
	const char *	event_name

void
bro_event_free (be)
	BroEvent *	be
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	bro_event_free(be);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

int
bro_event_add_val (be, type, type_name, val)
	BroEvent *	be
	int	type
	const char *	type_name
	const void *	val

int
bro_event_send (bc, be)
	BroConn *	bc
	BroEvent *	be

double
bro_util_current_time ()

BroRecord *
bro_record_new ()

int
bro_conn_get_fd (bc)
	BroConn *	bc

void
bro_event_registry_request (bc)
	BroConn *	bc
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	bro_event_registry_request(bc);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

