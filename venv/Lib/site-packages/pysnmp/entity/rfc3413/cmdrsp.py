#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
import sys

from pysnmp import debug
from pysnmp.proto import errind, error, rfc1902, rfc1905, rfc3411
from pysnmp.proto.api import v2c  # backend is always SMIv2 compliant
from pysnmp.proto.proxy import rfc2576
from pysnmp.smi import error as smi_error


# 3.2
class CommandResponderBase:
    ACM_ID = 3  # default MIB access control method to use
    SUPPORTED_PDU_TYPES = ()

    SMI_ERROR_MAP = {
        smi_error.TooBigError: "tooBig",
        smi_error.NoSuchNameError: "noSuchName",
        smi_error.BadValueError: "badValue",
        smi_error.ReadOnlyError: "readOnly",
        smi_error.GenError: "genErr",
        smi_error.NoAccessError: "noAccess",
        smi_error.WrongTypeError: "wrongType",
        smi_error.WrongLengthError: "wrongLength",
        smi_error.WrongEncodingError: "wrongEncoding",
        smi_error.WrongValueError: "wrongValue",
        smi_error.NoCreationError: "noCreation",
        smi_error.InconsistentValueError: "inconsistentValue",
        smi_error.ResourceUnavailableError: "resourceUnavailable",
        smi_error.CommitFailedError: "commitFailed",
        smi_error.UndoFailedError: "undoFailed",
        smi_error.AuthorizationError: "authorizationError",
        smi_error.NotWritableError: "notWritable",
        smi_error.InconsistentNameError: "inconsistentName",
    }

    def __init__(self, snmpEngine, snmpContext, cbCtx=None):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            snmpContext.contextEngineId, self.SUPPORTED_PDU_TYPES, self.processPdu
        )
        self.snmpContext = snmpContext
        self.cbCtx = cbCtx
        self.__pendingReqs = {}

    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acCtx):
        pass

    def close(self, snmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(
            self.snmpContext.contextEngineId, self.SUPPORTED_PDU_TYPES
        )
        self.snmpContext = self.__pendingReqs = None

    def sendVarBinds(
        self, snmpEngine, stateReference, errorStatus, errorIndex, varBinds
    ):
        (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            PDU,
            origPdu,
            maxSizeResponseScopedPDU,
            statusInformation,
        ) = self.__pendingReqs[stateReference]

        v2c.apiPDU.setErrorStatus(PDU, errorStatus)
        v2c.apiPDU.setErrorIndex(PDU, errorIndex)
        v2c.apiPDU.setVarBinds(PDU, varBinds)

        debug.logger & debug.FLAG_APP and debug.logger(
            "sendVarBinds: stateReference {}, errorStatus {}, errorIndex {}, varBinds {}".format(
                stateReference, errorStatus, errorIndex, varBinds
            )
        )

        self.sendPdu(snmpEngine, stateReference, PDU)

    def sendPdu(self, snmpEngine, stateReference, PDU):
        (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            _,
            origPdu,
            maxSizeResponseScopedPDU,
            statusInformation,
        ) = self.__pendingReqs[stateReference]

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v2ToV1(PDU, origPdu)

        # 3.2.6
        try:
            snmpEngine.msgAndPduDsp.returnResponsePdu(
                snmpEngine,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pduVersion,
                PDU,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation,
            )

        except error.StatusInformation:
            debug.logger & debug.FLAG_APP and debug.logger(
                f"sendPdu: stateReference {stateReference}, statusInformation {sys.exc_info()[1]}"
            )
            (
                snmpSilentDrops,
            ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
                "__SNMPv2-MIB", "snmpSilentDrops"
            )
            snmpSilentDrops.syntax += 1

    _getRequestType = rfc1905.GetRequestPDU.tagSet
    _getNextRequestType = rfc1905.GetNextRequestPDU.tagSet
    _setRequestType = rfc1905.SetRequestPDU.tagSet
    _counter64Type = rfc1902.Counter64.tagSet

    def releaseStateInformation(self, stateReference):
        if stateReference in self.__pendingReqs:
            del self.__pendingReqs[stateReference]

    def processPdu(
        self,
        snmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        maxSizeResponseScopedPDU,
        stateReference,
    ):
        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            origPdu = PDU
            PDU = rfc2576.v1ToV2(PDU)
        else:
            origPdu = None

        # 3.2.1
        if (
            PDU.tagSet not in rfc3411.READ_CLASS_PDUS
            and PDU.tagSet not in rfc3411.WRITE_CLASS_PDUS
        ):
            raise error.ProtocolError("Unexpected PDU class %s" % PDU.tagSet)

        # 3.2.2 --> no-op

        # 3.2.4
        rspPDU = v2c.apiPDU.getResponse(PDU)

        statusInformation = {}

        self.__pendingReqs[stateReference] = (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            rspPDU,
            origPdu,
            maxSizeResponseScopedPDU,
            statusInformation,
        )

        # 3.2.5
        varBinds = v2c.apiPDU.getVarBinds(PDU)

        debug.logger & debug.FLAG_APP and debug.logger(
            f"processPdu: stateReference {stateReference}, varBinds {varBinds}"
        )

        try:
            self.handleMgmtOperation(snmpEngine, stateReference, contextName, PDU)

        # SNMPv2 SMI exceptions
        except smi_error.SmiError:
            errorIndication = sys.exc_info()[1]

            debug.logger & debug.FLAG_APP and debug.logger(
                f"processPdu: stateReference {stateReference}, errorIndication {errorIndication}"
            )
            if "oid" in errorIndication:
                # Request REPORT generation
                statusInformation["oid"] = errorIndication["oid"]
                statusInformation["val"] = errorIndication["val"]

            errorStatus = self.SMI_ERROR_MAP.get(errorIndication.__class__, "genErr")

            try:
                errorIndex = errorIndication["idx"] + 1

            except KeyError:
                errorIndex = 1

            if len(varBinds) > errorIndex:
                errorIndex = 1

            # rfc1905: 4.2.1.3
            if errorStatus == "tooBig":
                errorIndex = 0
                varBinds = []

            # Report error
            self.sendVarBinds(
                snmpEngine, stateReference, errorStatus, errorIndex, varBinds
            )

        except smi_error.PySnmpError:
            debug.logger & debug.FLAG_APP and debug.logger(
                "processPdu: stateReference %s, error "
                "%s" % (stateReference, sys.exc_info()[1])
            )

        self.releaseStateInformation(stateReference)

    @classmethod
    def verifyAccess(cls, viewType, varBind, **context):
        name, val = varBind

        snmpEngine = context["snmpEngine"]

        execCtx = snmpEngine.observer.getExecutionContext(
            "rfc3412.receiveMessage:request"
        )
        (securityModel, securityName, securityLevel, contextName, pduType) = (
            execCtx["securityModel"],
            execCtx["securityName"],
            execCtx["securityLevel"],
            execCtx["contextName"],
            execCtx["pdu"].getTagSet(),
        )

        try:
            snmpEngine.accessControlModel[cls.ACM_ID].isAccessAllowed(
                snmpEngine,
                securityModel,
                securityName,
                securityLevel,
                viewType,
                contextName,
                name,
            )

        # Map ACM errors onto SMI ones
        except error.StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.FLAG_APP and debug.logger(
                f"__verifyAccess: name {name}, statusInformation {statusInformation}"
            )
            errorIndication = statusInformation["errorIndication"]
            # 3.2.5...
            if (
                errorIndication == errind.noSuchView
                or errorIndication == errind.noAccessEntry
                or errorIndication == errind.noGroupName
            ):
                raise smi_error.AuthorizationError(name=name, idx=context.get("idx"))

            elif errorIndication == errind.otherError:
                raise smi_error.GenError(name=name, idx=context.get("idx"))

            elif errorIndication == errind.noSuchContext:
                (
                    snmpUnknownContexts,
                ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
                    "__SNMP-TARGET-MIB", "snmpUnknownContexts"
                )
                snmpUnknownContexts.syntax += 1
                # Request REPORT generation
                raise smi_error.GenError(
                    name=name,
                    idx=context.get("idx"),
                    oid=snmpUnknownContexts.name,
                    val=snmpUnknownContexts.syntax,
                )

            elif errorIndication == errind.notInView:
                return True

            else:
                raise error.ProtocolError("Unknown ACM error %s" % errorIndication)
        else:
            # rfc2576: 4.1.2.1
            if (
                securityModel == 1
                and val is not None
                and cls._counter64Type == val.getTagSet()
                and cls._getNextRequestType == pduType
            ):
                # This will cause MibTree to skip this OID-value
                raise smi_error.NoAccessError(name=name, idx=context.get("idx"))


class GetCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetRequestPDU.tagSet,)

    # rfc1905: 4.2.1
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        # rfc1905: 4.2.1.1
        mgmtFun = self.snmpContext.getMibInstrum(contextName).readVars
        varBinds = v2c.apiPDU.getVarBinds(PDU)

        context = dict(snmpEngine=snmpEngine, acFun=self.verifyAccess, cbCtx=self.cbCtx)

        rspVarBinds = mgmtFun(*varBinds, **context)

        self.sendVarBinds(snmpEngine, stateReference, 0, 0, rspVarBinds)
        self.releaseStateInformation(stateReference)


class NextCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetNextRequestPDU.tagSet,)

    # rfc1905: 4.2.2
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        # rfc1905: 4.2.2.1
        mgmtFun = self.snmpContext.getMibInstrum(contextName).readNextVars

        varBinds = v2c.apiPDU.getVarBinds(PDU)

        context = dict(snmpEngine=snmpEngine, acFun=self.verifyAccess, cbCtx=self.cbCtx)

        while True:
            rspVarBinds = mgmtFun(*varBinds, **context)

            try:
                self.sendVarBinds(snmpEngine, stateReference, 0, 0, rspVarBinds)

            except error.StatusInformation:
                idx = sys.exc_info()[1]["idx"]
                varBinds[idx] = (rspVarBinds[idx][0], varBinds[idx][1])
            else:
                break

        self.releaseStateInformation(stateReference)


class BulkCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetBulkRequestPDU.tagSet,)
    maxVarBinds = 64

    # rfc1905: 4.2.3
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        nonRepeaters = v2c.apiBulkPDU.getNonRepeaters(PDU)
        if nonRepeaters < 0:
            nonRepeaters = 0

        maxRepetitions = v2c.apiBulkPDU.getMaxRepetitions(PDU)
        if maxRepetitions < 0:
            maxRepetitions = 0

        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)

        N = min(int(nonRepeaters), len(reqVarBinds))
        M = int(maxRepetitions)
        R = max(len(reqVarBinds) - N, 0)

        if R:
            M = min(M, self.maxVarBinds // R)

        debug.logger & debug.FLAG_APP and debug.logger(
            "handleMgmtOperation: N %d, M %d, R %d" % (N, M, R)
        )

        mgmtFun = self.snmpContext.getMibInstrum(contextName).readNextVars

        context = dict(snmpEngine=snmpEngine, acFun=self.verifyAccess, cbCtx=self.cbCtx)

        if N:
            # TODO(etingof): manage all PDU var-binds in a single call
            rspVarBinds = mgmtFun(*reqVarBinds[:N], **context)

        else:
            rspVarBinds = []

        varBinds = reqVarBinds[-R:]

        while M and R:
            rspVarBinds.extend(mgmtFun(*varBinds, **context))
            varBinds = rspVarBinds[-R:]
            M -= 1

        if len(rspVarBinds):
            self.sendVarBinds(snmpEngine, stateReference, 0, 0, rspVarBinds)
            self.releaseStateInformation(stateReference)
        else:
            raise smi_error.SmiError()


class SetCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.SetRequestPDU.tagSet,)

    # rfc1905: 4.2.5
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        mgmtFun = self.snmpContext.getMibInstrum(contextName).writeVars

        varBinds = v2c.apiPDU.getVarBinds(PDU)

        instrumError = None

        context = dict(snmpEngine=snmpEngine, acFun=self.verifyAccess, cbCtx=self.cbCtx)

        # rfc1905: 4.2.5.1-13
        try:
            rspVarBinds = mgmtFun(*varBinds, **context)

        except (
            smi_error.NoSuchObjectError,
            smi_error.NoSuchInstanceError,
        ):
            instrumError = smi_error.NotWritableError()
            instrumError.update(sys.exc_info()[1])

        else:
            self.sendVarBinds(snmpEngine, stateReference, 0, 0, rspVarBinds)

        self.releaseStateInformation(stateReference)

        if instrumError:
            raise instrumError
