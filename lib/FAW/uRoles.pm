# ABSTRACT: Модуль сопоставления и проверок ролей.

package FAW::uRoles;

use Moo;
use feature ':5.10';

use constant {
    OK => 0,
    ROLE_NOT_AT_LIST => 1,
    ROLE_INVERTED => 2,
    ACTION_DENY => 3,
    ROLE_MISTAKE_NAME => 4,
    ACTION_UNTYPIC => 5,
    ROLE_WRONG_FORMAT => 6,
};


=head1 Вспомогательные процедуры

Функциональные кирпичики.

=cut

=head2 complete_role
    
Дополняет роль правами доступа.

Если роль указана в неполном формате (без явно заданных
прав доступа), то считается, что роль имеет полные права доступа.
Однако такую роль следует дополнять дефолтными правами доступа.

=cut

sub complete_role {
    my ( $self, $role ) = @_;

    if   ( $role =~ /\+/ ) { }
    else                   { $role .= "+crud"; }

    return $role;
}

=head2 split_role

Разбирает роль, разделяя наименование роли и права роли.

Каждая роль может быть указана в сокращённом формате (без прав доступа). Тогда
эту роль следует дополнить полными правами (создание-чтение-обновление-
удаление) и разобрать на роль и на права.

=cut

sub split_role {
    my ( $self, $role ) = @_;
    $role =~ s/\s*//g;
    $role = $self->complete_role($role);
    $role =~ /^(!??)(\w+)\+(\w+)$/;
    return [ $1, $2, $3 ];
}

=head2 compare_roles

Сравнивает роли.

Процедура-заглушка. Ничего не делает.

=cut

sub compare_roles {
    my ( $user_role, $user_action );
    my ( $def_role, $def_action, $def_inverce );

    ( $user_role, $def_role ) = @_;

    say "$user_role";
}

=head2 translate_action

Сопоставляет WEB-запрос в букву действия. PUT, GET, POST, DELETE превращаются в C,R,U,D
соответственно.

Если действие неизвестно (нестандартное), то возвратит пустую строку.

=cut

sub translate_action {
    my ( $self, $action ) = @_;
    
    $action =~ s/^put$/c/i;
    $action =~ s/^get$/r/i;
    $action =~ s/^post$/u/i;
    $action =~ s/^delete$/d/i;
    
    return $action;
}

=head2 decode_status

Расшифровать статус.

Выполняет преобразование кода ошибки в краткое текстовое сообщение для
дальнейшего вывода.

=cut

sub decode_status {
    my ($self, $status) = @_;
    
    my $code = {
        OK => "all ok",
        ROLE_NOT_AT_LIST => "role not at list",
        ROLE_INVERTED => "inverted role",
        ACTION_DENY => "denied action",
        ROLE_MISTAKE_NAME => "mistake rolename",
        ACTION_UNTYPIC => "untypic action",
    };
    
    $status = $code->{$status} || "unknown status";
    return $status;
}


=head1 Основные процедуры

Основной функционал модуля.

=cut

=head2 check_role

Проверяет роль и действие текущего пользователя согласно переданному на
вход списку правил.

Возвращает OK при успехе (если правила разрешают пользователю предпринимать
запрошенное действие) или код ошибки, указывающий на причину запрета.

=item B<ROLE_NOT_AT_LIST>
роль отсутствует в списке;

=item B<ROLE_INVERTED>
роль инверсная, т.е. действие разрешается, если данная роль не
назначена пользователю;

=item B<ACTION_DENY>
запрошенное действие запрещается для этой роли;

=item B<ROLE_MISTAKE_NAME>
нетипичная роль (роль пользователя не может быть "any");

=item B<ACTION_UNTYPIC>
нетипичное действие;

=item B<ROLE_WRONG_FORMAT>
некорректное перечисление ролей;

=cut

sub check_role {
    my ( $self, $user_role, $user_action, $roles_list) = @_;
    my ( $def_inverce, $def_role, $def_action );
    my $deny_flag = 1;
    
    # роли действия указаны некорректно
    return ROLE_WRONG_FORMAT if ( $roles_list =~ /,/ );
    
    # роль пользователя не может быть ролью "для всех"
    foreach my $urole ( split(/\s/, $user_role) ) {
        ($def_inverce, $urole, $def_action) = @{$self->split_role($urole)};
        return ROLE_MISTAKE_NAME if ( $urole =~ /any|all/i ) ;
        
        # действие, запрошенное пользователем является нетипичным
        $user_action = $self->translate_action($user_action);
        return ACTION_UNTYPIC if ($user_action !~ /^[c|r|u|d]{1,4}$/);
        
        foreach my $current_role (split(/\s/, $roles_list)) {
            ( $def_inverce, $def_role, $def_action ) = @{$self->split_role($current_role)};
            if ( ( $def_role eq $urole ) || ( $def_role =~ /any|all/i ) ) {
                if ( $def_inverce eq "!" ) { return ROLE_INVERTED; }
                if ( $def_action =~ /$user_action/i ) { $deny_flag = 0; } 
                    else { $deny_flag = ACTION_DENY };
            }
        }
    };
    return $deny_flag;
}

__PACKAGE__->meta->make_immutable;

1;
