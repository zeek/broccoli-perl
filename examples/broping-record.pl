use 5.12.0;

use Broccoli::Connection qw/:types/;

my $b = Broccoli::Connection->new({destination => "localhost:47758"});

$b->event("pong", sub {
	my $rec = shift;

	say "pong - seq=$$rec{seq}, time=". ($$rec{dst_time}-$$rec{src_time})."/".(current_time()-$$rec{'src_time'});
});

$b->registerEvents();

my $seq = 0;
for (;;) {
	#$b->send("ping", btime(current_time()), count($seq++));
	$b->send("ping", {seq => count($seq++), src_time => btime(current_time()) });
	sleep(1);
}
