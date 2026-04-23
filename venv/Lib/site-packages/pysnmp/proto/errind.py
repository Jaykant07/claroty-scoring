#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#


class ErrorIndication(Exception):
    """SNMPv3 error-indication values"""

    def __init__(self, descr=None):
        self.__value = self.__descr = (
            self.__class__.__name__[0].lower() + self.__class__.__name__[1:]
        )
        if descr:
            self.__descr = descr

    def __eq__(self, other):
        return self.__value == other

    def __ne__(self, other):
        return self.__value != other

    def __lt__(self, other):
        return self.__value < other

    def __le__(self, other):
        return self.__value <= other

    def __gt__(self, other):
        return self.__value > other

    def __ge__(self, other):
        return self.__value >= other

    def __str__(self):
        return self.__descr


# SNMP message processing errors


class SerializationError(ErrorIndication):
    pass


serializationError = SerializationError(  # noqa: N816
    "SNMP message serialization error"
)


class DeserializationError(ErrorIndication):
    pass


deserializationError = DeserializationError(  # noqa: N816
    "SNMP message deserialization error"
)


class ParseError(DeserializationError):
    pass


parseError = ParseError("SNMP message deserialization error")  # noqa: N816


class UnsupportedMsgProcessingModel(ErrorIndication):
    pass


unsupportedMsgProcessingModel = UnsupportedMsgProcessingModel(  # noqa: N816
    "Unknown SNMP message processing model ID encountered"
)


class UnknownPDUHandler(ErrorIndication):
    pass


unknownPDUHandler = UnknownPDUHandler("Unhandled PDU type encountered")  # noqa: N816


class UnsupportedPDUtype(ErrorIndication):
    pass


unsupportedPDUtype = UnsupportedPDUtype(  # noqa: N816
    "Unsupported SNMP PDU type encountered"
)


class RequestTimedOut(ErrorIndication):
    pass


requestTimedOut = RequestTimedOut(  # noqa: N816
    "No SNMP response received before timeout"
)


class EmptyResponse(ErrorIndication):
    pass


emptyResponse = EmptyResponse("Empty SNMP response message")  # noqa: N816


class NonReportable(ErrorIndication):
    pass


nonReportable = NonReportable("Report PDU generation not attempted")  # noqa: N816


class DataMismatch(ErrorIndication):
    pass


dataMismatch = DataMismatch("SNMP request/response parameters mismatched")  # noqa: N816


class EngineIDMismatch(ErrorIndication):
    pass


engineIDMismatch = EngineIDMismatch("SNMP engine ID mismatch encountered")  # noqa: N816


class UnknownEngineID(ErrorIndication):
    pass


unknownEngineID = UnknownEngineID("Unknown SNMP engine ID encountered")  # noqa: N816


class TooBig(ErrorIndication):
    pass


tooBig = TooBig("SNMP message will be too big")  # noqa: N816


class LoopTerminated(ErrorIndication):
    pass


loopTerminated = LoopTerminated("Infinite SNMP entities talk terminated")  # noqa: N816


class InvalidMsg(ErrorIndication):
    pass


invalidMsg = InvalidMsg(  # noqa: N816
    "Invalid SNMP message header parameters encountered"
)


# SNMP security modules errors


class UnknownCommunityName(ErrorIndication):
    pass


unknownCommunityName = UnknownCommunityName(  # noqa: N816
    "Unknown SNMP community name encountered"
)


class NoEncryption(ErrorIndication):
    pass


noEncryption = NoEncryption("No encryption services configured")  # noqa: N816


class EncryptionError(ErrorIndication):
    pass


encryptionError = EncryptionError("Ciphering services not available")  # noqa: N816


class DecryptionError(ErrorIndication):
    pass


decryptionError = DecryptionError(  # noqa: N816
    "Ciphering services not available or ciphertext is broken"
)


class NoAuthentication(ErrorIndication):
    pass


noAuthentication = NoAuthentication(  # noqa: N816
    "No authentication services configured"
)


class AuthenticationError(ErrorIndication):
    pass


authenticationError = AuthenticationError(  # noqa: N816
    "Ciphering services not available or bad parameters"
)


class AuthenticationFailure(ErrorIndication):
    pass


authenticationFailure = AuthenticationFailure("Authenticator mismatched")  # noqa: N816


class UnsupportedAuthProtocol(ErrorIndication):
    pass


unsupportedAuthProtocol = UnsupportedAuthProtocol(  # noqa: N816
    "Authentication protocol is not supported"
)


class UnsupportedPrivProtocol(ErrorIndication):
    pass


unsupportedPrivProtocol = UnsupportedPrivProtocol(  # noqa: N816
    "Privacy protocol is not supported"
)


class UnknownSecurityName(ErrorIndication):
    pass


unknownSecurityName = UnknownSecurityName(  # noqa: N816
    "Unknown SNMP security name encountered"
)


class UnsupportedSecurityModel(ErrorIndication):
    pass


unsupportedSecurityModel = UnsupportedSecurityModel(  # noqa: N816
    "Unsupported SNMP security model"
)


class UnsupportedSecurityLevel(ErrorIndication):
    pass


unsupportedSecurityLevel = UnsupportedSecurityLevel(  # noqa: N816
    "Unsupported SNMP security level"
)


class NotInTimeWindow(ErrorIndication):
    pass


notInTimeWindow = NotInTimeWindow(  # noqa: N816
    "SNMP message timing parameters not in windows of trust"
)


class UnknownUserName(ErrorIndication):
    pass


unknownUserName = UnknownUserName("Unknown USM user")  # noqa: N816


class WrongDigest(ErrorIndication):
    pass


wrongDigest = WrongDigest("Wrong SNMP PDU digest")  # noqa: N816


class ReportPduReceived(ErrorIndication):
    pass


reportPduReceived = ReportPduReceived("Remote SNMP engine reported error")  # noqa: N816


# SNMP access-control errors


class NoSuchView(ErrorIndication):
    pass


noSuchView = NoSuchView("No such MIB view currently exists")  # noqa: N816


class NoAccessEntry(ErrorIndication):
    pass


noAccessEntry = NoAccessEntry("Access to MIB node denied")  # noqa: N816


class NoGroupName(ErrorIndication):
    pass


noGroupName = NoGroupName("No such VACM group configured")  # noqa: N816


class NoSuchContext(ErrorIndication):
    pass


noSuchContext = NoSuchContext("SNMP context now found")  # noqa: N816


class NotInView(ErrorIndication):
    pass


notInView = NotInView("Requested OID is out of MIB view")  # noqa: N816


class AccessAllowed(ErrorIndication):
    pass


accessAllowed = AccessAllowed()  # noqa: N816


class OtherError(ErrorIndication):
    pass


otherError = OtherError("Unspecified SNMP engine error occurred")  # noqa: N816


# SNMP Apps errors


class OidNotIncreasing(ErrorIndication):
    pass


oidNotIncreasing = OidNotIncreasing("OID not increasing")  # noqa: N816
