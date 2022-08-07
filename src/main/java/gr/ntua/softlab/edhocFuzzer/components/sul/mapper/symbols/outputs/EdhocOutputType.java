package gr.ntua.softlab.edhocFuzzer.components.sul.mapper.symbols.outputs;

/** Messages that can be received as responses.
 *  Possible additional responses not included are those generated from
 *  {@link gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.abstractSymbols.AbstractOutput#unknown() AbstractOutput.unknown()},
 *  {@link gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.abstractSymbols.AbstractOutput#socketClosed() AbstractOutput.socketClosed()},
 *  {@link gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.abstractSymbols.AbstractOutput#timeout() AbstractOutput.timeout()} */
public enum EdhocOutputType {
    EDHOC_MESSAGE_1,
    EDHOC_MESSAGE_2,
    EDHOC_MESSAGE_3,
    EDHOC_MESSAGE_4,
    APPLICATION_DATA,
    EDHOC_MESSAGE_3_COMBINED,
    EDHOC_ERROR_MESSAGE,
    COAP_ERROR_MESSAGE,
    EMPTY_COAP_ACK
}