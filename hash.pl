use strict;
use warnings;
use Data::Dumper qw(Dumper);
 
print crypt($ARGV[0], '$1$oNAuG282$') . "\n";
print crypt($ARGV[0], '$5$1bM59POonOkcgZVg$') . "\n";
print crypt($ARGV[0], '$6$1bM59POonOkcgZVg$') . "\n";

