use 5.10.1;

use Broccoli::Connection qw/:types/;
use Data::Dumper;

my $b = Broccoli::Connection->new(destination => "localhost:47758", guess_types => 1);
my $recv = 0;

$b->event("test2", sub {
	say "got event test2b";
	say Dumper(\@_);
	$recv++;
});

$b->event("test2b", sub {
	say "got event test2b";
	say Dumper(\@_);
});

$b->event("test4", sub {
	say "got event test4";
	say Dumper(\@_);
	$recv++;
});

$b->event("test7", sub {
	say "got event test7";
	say Dumper(\@_);
	$recv++;
});

$b->registerEvents();

$b->send("test1", 
		-10, 
		count(2), 
		btime(current_time()), 
		interval(120), 
		bool(0), 
		double(1.5), 
		"Servus", 
		"5555/tcp", 
		"6.7.6.5", 
		"192.168.0.0/16"
);

for(;;) {
	$b->process();
	if ( $recv == 2 ) {
		last;
	}
	sleep(1);
}

$b->send("test3", { a => 42, b => "6.6.7.7" });

$recv = 0;

for(;;) {
	$b->process();
	if ( $recv == 2 ) {
		last;
	}
	sleep(1);
}

$b->send("test5", { one => undef, a => 13, b => undef, c => "helloworld", d => "undef" } );

#$b->send("test6", { first => { a => 42, b => "6.6.7.7" }, second => { c => "hi" } } );
$b->send("test6", { first => { a => 42, b => "6.6.7.7" }, second => { c => "hi" } } );


sleep(1);

$recv = 0;

for(;;) {
	$b->process();
	if ( $recv == 1 ) {
		last;
	}
	sleep(1);
}

