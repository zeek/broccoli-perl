use 5.12.0;

use Broccoli::Connection qw/:types/;
use Data::Dumper;

my $b = Broccoli::Connection->new({destination => "localhost:47758"});

$b->event("test2", sub {
	say "got event test2";
	say Dumper(\@_);
});

$b->event("recd", sub {
	say "received";
});

$b->registerEvents();

my $seq = 0;
for (;;) {
	$b->send("test1", 
			-10, 
			count(2), 
			btime(current_time()), 
			interval(120), 
			bool(0), 
			double(1.5), 
			"Servus", 
			port("5555/tcp"), 
			addr("6.7.6.5"), 
			subnet("192.168.0.0/16")
	);
	sleep(1);
}
