package gr.ntua.softlab.edhocFuzzer.components.sul.mapper.symbols;

import gr.ntua.softlab.edhocFuzzer.components.sul.core.protocol.ApplicationDataMessage;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.core.protocol.ProtocolMessage;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.abstractSymbols.AbstractOutput;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.context.ExecutionContext;

public class ApplicationDataInput extends EdhocInput {

    @Override
    public void preSendUpdate(ExecutionContext context) {
        getEdhocMapperState(context).setupOscoreContext();
    }

    @Override
    public ProtocolMessage generateProtocolMessage(ExecutionContext context) {
        return new ApplicationDataMessage();
    }

    @Override
    public void postSendUpdate(ExecutionContext context) {
    }

    @Override
    public void postReceiveUpdate(AbstractOutput output, ExecutionContext context) {
    }

    @Override
    public Enum<EdhocInputType> getInputType() {
        return EdhocInputType.APPLICATION_DATA_MESSAGE;
    }
}
