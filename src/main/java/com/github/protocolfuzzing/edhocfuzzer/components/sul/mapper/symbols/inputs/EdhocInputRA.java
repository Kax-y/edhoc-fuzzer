package com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.inputs;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.EdhocSessionPersistent;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.EdhocUtil;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.EdhocProtocolMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocExecutionContextRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.outputs.EdhocOutputRA;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.MapperInput;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import com.upokecenter.cbor.CBORObject;
import de.learnlib.ralib.data.DataType;
import de.learnlib.ralib.data.DataValue;
import de.learnlib.ralib.words.PSymbolInstance;
import de.learnlib.ralib.words.ParameterizedSymbol;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class EdhocInputRA extends PSymbolInstance
        implements MapperInput<EdhocOutputRA, EdhocProtocolMessage, EdhocExecutionContextRA> {

    private long extendedWait = 0;
    protected DataType T_CI = new DataType("C_I", Integer.class);

    private static Logger LOGGER = LogManager.getLogger();

    EdhocInputRA(ParameterizedSymbol baseSymbol, DataValue<?>... parameterValues) {
        super(baseSymbol, parameterValues);
    }

    public abstract Enum<MessageInputType> getInputType();

    @Override
    public void preSendUpdate(EdhocExecutionContextRA context) {
    }

    @Override
    public void postSendUpdate(EdhocExecutionContextRA context) {
    }

    @Override
    public void postReceiveUpdate(
            EdhocOutputRA output,
            OutputChecker<EdhocOutputRA> abstractOutputChecker,
            EdhocExecutionContextRA context) {
    }

    @Override
    public Long getExtendedWait() {
        return extendedWait;
    }

    @Override
    public void setExtendedWait(Long value) {
        extendedWait = value;
    }

    @Override
    public String getName() {
        return this.getBaseSymbol().getName();
    }

    public DataType[] getDataTypes() {
        return this.getBaseSymbol().getPtypes();
    }

    /*
     * TODO This is bad in multiple ways:
     * - We need to have access to the datatype, which means defining it multiple
     * times. For teachers, EdhocInputRA and the EdhocOutputMapperRA.
     * - If the C_I is a bytestring it is unclear if use of a mapper to convert from
     * a randomly selected integer in the learner to a corresponding bytestring is
     * possible.
     */
    public void updateConnectionId(EdhocSessionPersistent session) {

        LOGGER.info("Running updateConnectionId method");
        LOGGER.info("Current ConnectionId: " + EdhocUtil.bytesToInt(session.getConnectionId()));

        for (DataValue<?> dv : this.getParameterValues()) {

            LOGGER.info("Datavalue: " + dv.toString());
            if (dv.getType().equals(T_CI)) {
                CBORObject value = CBORObject.FromObject(dv.getId());
                LOGGER.info("CBORObject version of DataValue id: " + value.toString());

                session.setConnectionId(value.EncodeToBytes());
                LOGGER.info(
                        "Current ConnectionId after set: " + EdhocUtil.bytesToInt(session.getConnectionId()));
            }
        }
    }
}