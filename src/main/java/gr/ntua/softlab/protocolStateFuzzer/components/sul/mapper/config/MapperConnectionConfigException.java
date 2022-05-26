package gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.config;

public class MapperConnectionConfigException extends RuntimeException {
    public MapperConnectionConfigException() {
        super();
    }

    public MapperConnectionConfigException(String message) {
        super(message);
    }

    public MapperConnectionConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
