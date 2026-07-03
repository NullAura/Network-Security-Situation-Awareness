package edu.bigdata.honeypot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.flink.api.common.restartstrategy.RestartStrategies;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.sink.RichSinkFunction;
import org.apache.flink.streaming.api.functions.source.RichParallelSourceFunction;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

public class HoneypotFlinkStreamJob {
    private static final Map<String, SourceInfo> TOPIC_SOURCES = new HashMap<>();

    static {
        TOPIC_SOURCES.put(
                "honeypot_cowrie_clean",
                new SourceInfo("203.0.113.10", "/var/log/honeypot-preprocessed/events.jsonl"));
        TOPIC_SOURCES.put(
                "honeypot_opencanary_clean",
                new SourceInfo("203.0.113.11", "/var/log/honeypot-preprocessed/events.jsonl"));
        TOPIC_SOURCES.put(
                "honeypot3_clean",
                new SourceInfo("203.0.113.12", "/var/log/honeypot-preprocessed/events.jsonl"));
    }

    public static void main(String[] args) throws Exception {
        JobOptions options = JobOptions.parse(args);
        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        env.setParallelism(1);
        env.setRestartStrategy(RestartStrategies.fixedDelayRestart(20, 5000));

        env.addSource(new KafkaPollingSource(options))
                .name("Kafka clean honeypot topics")
                .uid("honeypot-kafka-source")
                .addSink(new StreamFileSink(options.dataDir, options.zoneId))
                .name("Write compatible stream JSONL")
                .uid("honeypot-stream-file-sink");

        env.execute("honeypot-flink-stream");
    }

    public static class KafkaEnvelope implements Serializable {
        public String topic;
        public int partition;
        public long offset;
        public long kafkaTimestamp;
        public String value;

        public KafkaEnvelope() {
        }

        public KafkaEnvelope(String topic, int partition, long offset, long kafkaTimestamp, String value) {
            this.topic = topic;
            this.partition = partition;
            this.offset = offset;
            this.kafkaTimestamp = kafkaTimestamp;
            this.value = value;
        }
    }

    private static class SourceInfo implements Serializable {
        final String source;
        final String path;

        SourceInfo(String source, String path) {
            this.source = source;
            this.path = path;
        }
    }

    private static class JobOptions implements Serializable {
        String bootstrapServer = "203.0.113.20:9092";
        String groupId = "honeypot-flink-stream-writer";
        String dataDir = "/data/honeypot/stream";
        String autoOffsetReset = "latest";
        String topics = String.join(",", TOPIC_SOURCES.keySet());
        int pollTimeoutMs = 1000;
        int maxPollRecords = 500;
        ZoneId zoneId = ZoneId.systemDefault();

        static JobOptions parse(String[] args) {
            JobOptions options = new JobOptions();
            for (int i = 0; i < args.length; i++) {
                String key = args[i];
                String value = i + 1 < args.length ? args[i + 1] : "";
                switch (key) {
                    case "--bootstrap-server":
                        options.bootstrapServer = value;
                        i++;
                        break;
                    case "--group-id":
                        options.groupId = value;
                        i++;
                        break;
                    case "--data-dir":
                        options.dataDir = value;
                        i++;
                        break;
                    case "--auto-offset-reset":
                        options.autoOffsetReset = value.toLowerCase(Locale.ROOT);
                        i++;
                        break;
                    case "--topics":
                        options.topics = value;
                        i++;
                        break;
                    case "--poll-timeout-ms":
                        options.pollTimeoutMs = Integer.parseInt(value);
                        i++;
                        break;
                    case "--max-poll-records":
                        options.maxPollRecords = Integer.parseInt(value);
                        i++;
                        break;
                    case "--timezone":
                        options.zoneId = ZoneId.of(value);
                        i++;
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown argument: " + key);
                }
            }
            return options;
        }

        List<String> topicList() {
            return Arrays.asList(topics.split("\\s*,\\s*"));
        }
    }

    private static class KafkaPollingSource extends RichParallelSourceFunction<KafkaEnvelope> {
        private final JobOptions options;
        private transient KafkaConsumer<byte[], byte[]> consumer;
        private volatile boolean running = true;

        KafkaPollingSource(JobOptions options) {
            this.options = options;
        }

        @Override
        public void run(SourceContext<KafkaEnvelope> ctx) {
            Properties props = new Properties();
            props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, options.bootstrapServer);
            props.put(ConsumerConfig.GROUP_ID_CONFIG, options.groupId);
            props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, options.autoOffsetReset);
            props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true");
            props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, "1000");
            props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, Integer.toString(options.maxPollRecords));
            props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
            props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());

            consumer = new KafkaConsumer<>(props);
            consumer.subscribe(options.topicList());
            while (running) {
                ConsumerRecords<byte[], byte[]> records = consumer.poll(Duration.ofMillis(options.pollTimeoutMs));
                for (ConsumerRecord<byte[], byte[]> record : records) {
                    String value = record.value() == null
                            ? ""
                            : new String(record.value(), StandardCharsets.UTF_8).replaceAll("[\\r\\n]+$", "");
                    synchronized (ctx.getCheckpointLock()) {
                        ctx.collect(new KafkaEnvelope(
                                record.topic(),
                                record.partition(),
                                record.offset(),
                                record.timestamp(),
                                value));
                    }
                }
            }
            consumer.close();
        }

        @Override
        public void cancel() {
            running = false;
            if (consumer != null) {
                consumer.wakeup();
            }
        }
    }

    private static class StreamFileSink extends RichSinkFunction<KafkaEnvelope> {
        private final String dataDir;
        private final ZoneId zoneId;
        private transient ObjectMapper mapper;
        private transient Map<Path, BufferedWriter> writers;

        StreamFileSink(String dataDir, ZoneId zoneId) {
            this.dataDir = dataDir;
            this.zoneId = zoneId;
        }

        @Override
        public void open(Configuration parameters) {
            mapper = new ObjectMapper();
            writers = new ConcurrentHashMap<>();
        }

        @Override
        public void invoke(KafkaEnvelope envelope, Context context) throws Exception {
            if (envelope == null || envelope.value == null || envelope.value.isBlank()) {
                return;
            }
            SourceInfo sourceInfo = TOPIC_SOURCES.getOrDefault(
                    envelope.topic,
                    new SourceInfo("unknown", "/var/log/honeypot-preprocessed/events.jsonl"));
            String day = LocalDate.now(zoneId).toString();
            Path target = Paths.get(dataDir, day, safeFileName(sourceInfo.source) + ".jsonl");
            BufferedWriter writer = writerFor(target);

            ObjectNode output = mapper.createObjectNode();
            output.put("received_at", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
            output.put("source", sourceInfo.source);
            output.put("source_ip", sourceInfo.source);
            output.put("path", sourceInfo.path);
            output.put("sent_at", "");
            output.put("line", envelope.value);
            output.put("kafka_topic", envelope.topic);
            output.put("kafka_partition", envelope.partition);
            output.put("kafka_offset", envelope.offset);
            output.put("kafka_timestamp", envelope.kafkaTimestamp);
            output.put("processing_engine", "flink");

            writer.write(mapper.writeValueAsString(output));
            writer.newLine();
            writer.flush();
        }

        @Override
        public void close() throws IOException {
            if (writers == null) {
                return;
            }
            for (BufferedWriter writer : writers.values()) {
                writer.close();
            }
        }

        private BufferedWriter writerFor(Path path) throws IOException {
            BufferedWriter existing = writers.get(path);
            if (existing != null) {
                return existing;
            }
            Files.createDirectories(path.getParent());
            BufferedWriter created = Files.newBufferedWriter(
                    path,
                    StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
            writers.put(path, created);
            return created;
        }

        private static String safeFileName(String value) {
            String cleaned = value.replaceAll("[^A-Za-z0-9_.-]", "_");
            return cleaned.isBlank() ? "unknown" : cleaned;
        }
    }
}
