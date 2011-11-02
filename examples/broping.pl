use 5.12.0;

use Broccoli::Connection qw/:types/;

my $b = Broccoli::Connection->new({destination => "localhost:47758"});

$b->event("pong", sub {
	my ($src_time, $dst_time, $seq) = @_;

	say "pong - seq=$seq, time=". ($dst_time-$src_time)."/".($b->current_time()-$src_time);
});

$b->registerEvents();

my $seq = 0;
for (;;) {
	$b->send("ping", btime(current_time()), count($seq++));
	sleep(1);
}
