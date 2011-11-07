use 5.10.1;
use ExtUtils::MakeMaker;

my $cflags = $ENV{"CCFLAGS"};
$cflags //= "";
my $ldflags = $ENV{"LDDFLAGS"};
$ldflags //= "";

WriteMakefile( NAME => 'Broccoli::Connection',
               VERSION_FROM => 'Connection.pm',
	       CCFLAGS => $cflags, 
	       LIBS => [ $ldflags." -lbroccoli" ],
             );
