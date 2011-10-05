use 5.12.0;

use Broccoli::Connection;

my $b = Broccoli::Connection->new({destination => "localhost:47757"});

$b->event("pong", sub {
	my ($src_time, $dst_time, $seq) = @_;

	say "pong - seq=$seq, time=". ($dst_time-$src_time)."/".($b->current_time()-$src_time);
});

my $seq = 0;
for (;;) {
	$b->send("ping", $b->time($b->current_time()), $b->count($seq++));
	sleep(1);
}
