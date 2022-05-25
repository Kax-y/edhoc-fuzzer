package gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.config;

import com.beust.jcommander.Parameter;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.abstractSymbols.AbstractOutput;

import java.util.List;

/**
 * Configures how actual messages are mapped to abstract output strings.
 */
public class MapperConfig {
    @Parameter(names = "-repeatingOutputs", description = "Single or repeated occurrences of these "
            + "outputs are mapped to a single repeating output (e.g. CLIENT_HELLO is mapped to "
            + "CLIENT_HELLO" + AbstractOutput.REPEATING_INDICATOR + " ). "
            + "Used for outputs that the SUL may repeat an arbitrary number of times which may cause non-determinism.")
    protected List<String> repeatingOutputs = null;

    @Parameter(names = "-socketClosedAsTimeout", description = "Uses " + AbstractOutput.TIMEOUT + " instead of "
            + AbstractOutput.SOCKET_CLOSED + " outputs to identify when the system process is dead. "
            + "Useful for preventing non-determinism due to the arbitrary duration "
            + "from when the system stops responding to when its process eventually dies. ")
    protected boolean socketClosedAsTimeout = false;

    @Parameter(names = "-disabledAsTimeout", description = "Uses " + AbstractOutput.TIMEOUT + " instead of "
            + AbstractOutput.DISABLED)
    protected boolean disabledAsTimeout = false;

    @Parameter(names = "-dontMergeRepeating", description = "Disables merging of repeated outputs. "
            + "By default the mapper merges outputs which are repeated in succession (e.g. CLIENT_HELLO,CLIENT_HELLO) "
            + "into a single output to which '" + AbstractOutput.REPEATING_INDICATOR + "' is post-pended "
            + "(CLIENT_HELLO" + AbstractOutput.REPEATING_INDICATOR + ")")
    protected boolean dontMergeRepeating = false;

    public List<String> getRepeatingOutputs() {
        return repeatingOutputs;
    }

    public boolean isSocketClosedAsTimeout() {
        return socketClosedAsTimeout;
    }

    public boolean isDisabledAsTimeout() {
        return disabledAsTimeout;
    }

    public boolean isMergeRepeating() {
        return !dontMergeRepeating;
    }
}
