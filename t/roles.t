#
#===============================================================================
#
#         FILE: roles.t
#
#  DESCRIPTION:
#
#        FILES: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: YOUR NAME (),
#      COMPANY:
#      VERSION: 1.0
#      CREATED: 22.08.2012 21:24:40
#     REVISION: ---
#===============================================================================

use strict;
use warnings;

use Test::More;    # last test to print

my $roleslist1 = '!guest+r, user+cru';
my $roleslist2 = '!admin';
my $roleslist3 = 'any+r';

my $rolearr1 = [ '',  'admin', 'crud' ];
my $rolearr2 = [ '!', 'guest', 'cud' ];

BEGIN { use_ok('FAW::uRoles'); }
require_ok('FAW::uRoles');

my $fawroles = new_ok("FAW::uRoles");

is( $fawroles->complete_role('guest'),
    'guest+crud', 'корректно расширены права роли' );
is( $fawroles->complete_role('guest+cu'), 'guest+cu',
    'существующие права роли не дополняются');

is_deeply( $fawroles->split_role("admin"), $rolearr1,
    'корректный разбор с дополнением аргументами');
is_deeply( $fawroles->split_role("!guest+cud"), $rolearr2,
    'корректный разбор полного инверсного правила');

is( $fawroles->check_role( 'any', 'GET', $roleslist1 ), 4,
    'any = ' .$roleslist1. ' : запрет. роль any запрещено назначать пользователю. Будет всегда запрет.' );

is( $fawroles->check_role( 'guest', 'GET', $roleslist1 ), 2,
    'guest = ' .$roleslist1. ' : запрет. роль разрешена для не-гостей' );
is( $fawroles->check_role( 'user', 'PUT', $roleslist1 ), 0,
    'user = ' .$roleslist1. ' : доступ. пользователь может добавлять что-то');
is( $fawroles->check_role( 'user', 'DELETE', $roleslist1 ), 3,
    'user = ' .$roleslist1. ' : запрет. пользователь не может удалять материал');
is( $fawroles->check_role( 'admin', 'GET', $roleslist1 ), 1,
    'admin = ' .$roleslist1. ' : запрет. админа вообще нет в списке ролей' );

is( $fawroles->check_role( 'admin', 'GET', $roleslist2 ), 2,
    'admin = ' .$roleslist2. ' : запрет. разрешено для не-админов' );

# очень интересное поведение: если указана роль не-админ, но не указана явно
# другая роль, доступ не-админам предоставлен всё равно не будет.
is( $fawroles->check_role( 'user', 'GET', $roleslist2 ), 1,
    'user = ' .$roleslist2. ' : запрет. разрешено для не-админов, но других ролей в списке не указано' );
is( $fawroles->check_role( 'guest', 'DELETE', $roleslist2 ), 1,
    'guest = ' .$roleslist2. ' : запрет. разрешено для не-админов, но других ролей в списке не указано' );

is( $fawroles->check_role( 'guest', 'DELETE', $roleslist3 ), 3,
    'guest = ' .$roleslist3. ' : запрет. разрешено только чтение' );
is( $fawroles->check_role( 'user', 'GET', $roleslist3 ), 0,
    'user = ' .$roleslist3. ' : доступ. разрешено только чтение' );
is( $fawroles->check_role( 'user', 'get', $roleslist3 ), 0,
    'user = ' .$roleslist3. ' : доступ. регистр имени действия значения не имеет' );
is( $fawroles->check_role( 'user', 'gett', $roleslist3 ), 5,
    'user = ' .$roleslist3. ' : запрет. действие должно находится в разрешённом списке' );

done_testing;
