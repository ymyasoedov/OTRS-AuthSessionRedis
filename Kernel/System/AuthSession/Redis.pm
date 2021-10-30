# --
# Copyright (C) 2020 Yuri Myasoedov <ymyasoedov@yandex.ru>
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see https://www.gnu.org/licenses/gpl-3.0.txt.
# --

package Kernel::System::AuthSession::Redis;

use strict;
use warnings;

use Kernel::Language qw(Translatable);
use Kernel::System::VariableCheck qw(IsHashRefWithData);

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::DateTime',
    'Kernel::System::Log',
    'Kernel::System::Main',
    'Kernel::System::Storable',
);

sub new {
    my ( $Type, %Param ) = @_;

    my $Self = {};
    bless( $Self, $Type );

    # Store Redis config
    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    $Self->{Config} = {
        Address        => $ConfigObject->Get('AuthSession::Redis')->{Server}         || '127.0.0.1:6379',
        DatabaseNumber => $ConfigObject->Get('AuthSession::Redis')->{DatabaseNumber} || 1,
        RedisFast      => $ConfigObject->Get('AuthSession::Redis')->{RedisFast}      || 0,
    };

    # Not connected yet
    $Self->{Redis} = undef;

    return $Self;
}

sub DESTROY {
    my ( $Self, %Param ) = @_;

    return 1 if !$Self->{Cache};

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    SESSIONID:
    for my $SessionID ( keys %{ $Self->{UpdateCache} } ) {

        next SESSIONID if !$SessionID;

        # get session data
        my %Session = $Self->GetSessionIDData( SessionID => $SessionID );
        next SESSIONID if !%Session;

        # serialize session data
        my $DataContent = $Kernel::OM->Get('Kernel::System::Storable')->Serialize(
            Data => \%Session,
        );

        # update session data in redis and set the same TTL
        my $TTL = $Self->{Redis}->ttl( "OTRSSession-" . $SessionID );
        next SESSIONID if !$TTL;
        $Self->{Redis}->setex( 'OTRSSession-' . $SessionID, $TTL, $DataContent );

    }

    return 1;
}

sub CheckSessionID {
    my ( $Self, %Param ) = @_;

    # check session id
    if ( !$Param{SessionID} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Got no SessionID!!'
        );
        return;
    }

    my $RemoteAddr = $ENV{REMOTE_ADDR} || 'none';

    # set default message
    $Self->{SessionIDErrorMessage} = Translatable('Session invalid. Please log in again.');

    # get session data
    my %Data = $Self->GetSessionIDData( SessionID => $Param{SessionID} );
    return if !%Data;

    if ( !$Data{UserID} || !$Data{UserLogin} ) {
        $Self->{SessionIDErrorMessage} = Translatable('Session invalid. Please log in again.');
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message  => "SessionID: '$Param{SessionID}' is invalid!!!",
        );
        return;
    }

    # get config object
    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # remote ip check
    if (
        $Data{UserRemoteAddr} ne $RemoteAddr
        && $ConfigObject->Get('SessionCheckRemoteIP')
        )
    {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message  => "RemoteIP of '$Param{SessionID}' ($Data{UserRemoteAddr}) is "
                . "different from registered IP ($RemoteAddr). Invalidating session! "
                . "Disable config 'SessionCheckRemoteIP' if you don't want this!",
        );

        # delete session id if it isn't the same remote ip?
        if ( $ConfigObject->Get('SessionDeleteIfNotRemoteID') ) {
            $Self->RemoveSessionID( SessionID => $Param{SessionID} );
        }

        return;
    }

    # we don't need to check session idle time, because this function
    # does by redis itself, we will check only max session time
    my $TimeNow = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

    # check session max time
    my $MaxSessionTime = $ConfigObject->Get('SessionMaxTime');

    if ( $Data{UserSessionStart} + $MaxSessionTime < $TimeNow ) {
        $Self->{SessionIDErrorMessage} = Translatable('Session has timed out. Please log in again.');

        my $Timeout = int( ( $TimeNow - $Data{UserSessionStart} ) / ( 60 * 60 ) );

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message  => "SessionID ($Param{SessionID}) too old ($Timeout h)! Don't grant access!!!",
        );

        # delete session id if too old
        if ( $ConfigObject->Get('SessionDeleteIfTimeToOld') ) {
            $Self->RemoveSessionID( SessionID => $Param{SessionID} );
        }

        return;
    }

    return 1;
}

sub SessionIDErrorMessage {
    my ( $Self, %Param ) = @_;

    return $Self->{SessionIDErrorMessage} || '';
}

sub GetSessionIDData {
    my ( $Self, %Param ) = @_;

    # check session id
    if ( !$Param{SessionID} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Got no SessionID!!'
        );
        return;
    }

    # check cache
    if ( $Self->{Cache}->{ $Param{SessionID} } ) {
        if ( $Self->{UpdateCache}->{ $Param{SessionID} } ) {
            return ( %{ $Self->{Cache}->{ $Param{SessionID} } }, %{ $Self->{UpdateCache}->{ $Param{SessionID} } } );
        }
        else {
            return %{ $Self->{Cache}->{ $Param{SessionID} } };
        }
    }

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    # get data from redis
    my $Content = $Self->{Redis}->get( 'OTRSSession-' . $Param{SessionID} );
    return if !$Content;

    # read data structure back from file dump, use block eval for safety reasons
    my $SessionData = eval {
        $Kernel::OM->Get('Kernel::System::Storable')->Deserialize( Data => $Content );
    };

    if ( !IsHashRefWithData($SessionData) ) {
        delete $Self->{UpdateCache}->{ $Param{SessionID} };
        return;
    }

    # cache result
    $Self->{Cache}->{ $Param{SessionID} } = $SessionData;

    if ( $Self->{UpdateCache}->{ $Param{SessionID} } ) {
        return ( %{ $Self->{Cache}->{ $Param{SessionID} } }, %{ $Self->{UpdateCache}->{ $Param{SessionID} } } );
    }

    return %{ $Self->{Cache}->{ $Param{SessionID} } };
}

sub CreateSessionID {
    my ( $Self, %Param ) = @_;

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    # get system time
    my $TimeNow = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

    # get remote address and the http user agent
    my $RemoteAddr      = $ENV{REMOTE_ADDR}     || 'none';
    my $RemoteUserAgent = $ENV{HTTP_USER_AGENT} || 'none';

    my $MainObject   = $Kernel::OM->Get('Kernel::System::Main');
    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # create session id
    my $SessionID = $ConfigObject->Get('SystemID') . $MainObject->GenerateRandomString(
        Length => 32,
    );

    # create challenge token
    my $ChallengeToken = $MainObject->GenerateRandomString(
        Length => 32,
    );

    my %Data;
    KEY:
    for my $Key ( sort keys %Param ) {

        next KEY if !$Key;

        $Data{$Key} = $Param{$Key};
    }

    my $MaxSessionIdleTime = $ConfigObject->Get('SessionMaxIdleTime');
    my $MaxSessionTime     = $ConfigObject->Get('SessionMaxTime');

    $Data{UserSessionStart}    = $TimeNow;
    $Data{UserRemoteAddr}      = $RemoteAddr;
    $Data{UserRemoteUserAgent} = $RemoteUserAgent;
    $Data{UserChallengeToken}  = $ChallengeToken;

    # dump the data
    my $DataContent = $Kernel::OM->Get('Kernel::System::Storable')->Serialize( Data => \%Data );

    # store session in redis
    if ($MaxSessionIdleTime) {
        $Self->{Redis}->setex( 'OTRSSession-' . $SessionID, $MaxSessionIdleTime, $DataContent );
    }
    else {
        $Self->{Redis}->set( 'OTRSSession-' . $SessionID, $DataContent );
    }

    return $SessionID;
}

sub RemoveSessionID {
    my ( $Self, %Param ) = @_;

    if ( !$Param{SessionID} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Got no SessionID!!'
        );
    }

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    $Self->{Redis}->del( 'OTRSSession-' . $Param{SessionID} );

    delete $Self->{Cache}->{ $Param{SessionID} };
    delete $Self->{UpdateCache}->{ $Param{SessionID} };

    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'notice',
        Message  => "Removed SessionID $Param{SessionID}."
    );

    return 1;
}

sub UpdateSessionID {
    my ( $Self, %Param ) = @_;

    for (qw(SessionID Key)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $_!"
            );
            return;
        }
    }

    $Self->{UpdateCache}->{ $Param{SessionID} }->{ $Param{Key} } = $Param{Value};

    return 1;
}

sub GetAllSessionIDs {
    my ( $Self, %Param ) = @_;

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    return map { ( split( 'OTRSSession\-', $_ ) )[-1] } $Self->{Redis}->keys('OTRSSession-*');

}

sub GetActiveSessions {
    my ( $Self, %Param ) = @_;

    # get all available sessions
    my @SessionIDs = $Self->GetAllSessionIDs();

    my $ActiveSessionCount = 0;
    my %ActiveSessionPerUserCount;

    # Sessions IDLE contolled by Redis TTL mechanism,
    # so no need in additional checks

    SESSIONID:
    for my $SessionID (@SessionIDs) {

        next SESSIONID if !$SessionID;

        # get session data
        my %Session = $Self->GetSessionIDData( SessionID => $SessionID );

        next SESSIONID if !%Session;

        # Don't count session from source 'GenericInterface'
        my $SessionSource = $Session{SessionSource} || '';

        next SESSIONID if $SessionSource eq 'GenericInterface';

        # get needed data
        my $UserType  = $Session{UserType} || '';
        my $UserLogin = $Session{UserLogin};

        next SESSIONID if $UserType ne $Param{UserType};

        $ActiveSessionCount++;

        $ActiveSessionPerUserCount{$UserLogin} || 0;
        $ActiveSessionPerUserCount{$UserLogin}++;

    }

    return (
        Total   => $ActiveSessionCount,
        PerUser => \%ActiveSessionPerUserCount,
    );
}

=head2 GetExpiredSessionIDs()

for redis there is no expired idles, only expired sessions,
because idle TTL is controlled by redis

=cut

sub GetExpiredSessionIDs {
    my ( $Self, %Param ) = @_;

    my $MaxSessionTime = $Kernel::OM->Get('Kernel::Config')->Get('SessionMaxTime');

    my $TimeNow = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

    my @SessionIDs = $Self->GetAllSessionIDs();
    my @ExpiredSessions;

    SESSIONID:
    for my $SessionID (@SessionIDs) {
        my %Session = $Self->GetSessionIDData( SessionID => $SessionID );

        next SESSIONID if !%Session;

        my $UserSessionStart = $Session{UserSessionStart} || $TimeNow;

        if ( $TimeNow - $UserSessionStart > $MaxSessionTime ) {
            push @ExpiredSessions, $SessionID;
        }
    }

    return ( \@ExpiredSessions, [] );
}

sub CleanUp {
    my ( $Self, %Param ) = @_;

    # Connect to Redis if not connected
    return if !$Self->{Redis} && !$Self->_Connect();

    # just flush current db
    $Self->{Redis}->flushdb();

    return 1;
}

sub _Connect {
    my $Self = shift;

    return if $Self->{Redis};

    my $MainObject = $Kernel::OM->Get('Kernel::System::Main');
    my $Loaded     = $MainObject->Require(
        $Self->{Config}{RedisFast} ? 'Redis::Fast' : 'Redis',
    );
    return if !$Loaded;

    eval {
        if ( $Self->{Config}{RedisFast} ) {
            $Self->{Redis} = Redis::Fast->new( server => $Self->{Config}{Address} );
        }
        else {
            $Self->{Redis} = Redis->new( server => $Self->{Config}{Address} );
        }
        if (
            $Self->{Config}{DatabaseNumber}
            && !$Self->{Redis}->select( $Self->{Config}{DatabaseNumber} )
            )
        {
            die "Can't select database '$Self->{Config}{DatabaseNumber}'!";
        }
    };
    if ($@) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Redis error: $@!",
        );
        $Self->{Redis} = undef;
        return;
    }

    return 1;
}

1;

=head1 TERMS AND CONDITIONS

This software is part of the OTRS project (L<https://otrs.org/>).

This software comes with ABSOLUTELY NO WARRANTY. For details, see
the enclosed file COPYING for license information (GPL). If you
did not receive this file, see L<https://www.gnu.org/licenses/gpl-3.0.txt>.

=cut
