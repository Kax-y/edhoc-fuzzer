package gr.ntua.softlab.edhocFuzzer.components.sul.mapper.symbols.inputs;

import gr.ntua.softlab.edhocFuzzer.components.sul.core.protocol.messages.ApplicationDataMessage;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.core.protocol.ProtocolMessage;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.context.ExecutionContext;

public class ApplicationDataInput extends EdhocInput {
    @Override
    public ProtocolMessage generateProtocolMessage(ExecutionContext context) {
        return new ApplicationDataMessage();
    }

    @Override
    public Enum<EdhocInputType> getInputType() {
        return EdhocInputType.APPLICATION_DATA;
    }
}