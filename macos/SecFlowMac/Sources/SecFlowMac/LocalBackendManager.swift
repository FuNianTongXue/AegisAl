import Darwin
import Foundation

enum LocalBackendError: LocalizedError {
    case executableMissing
    case unavailable(String)

    var errorDescription: String? {
        switch self {
        case .executableMissing:
            return "应用内本地服务缺失，请重新安装 SecFlow。"
        case let .unavailable(detail):
            return "本地服务启动失败：\(detail)"
        }
    }
}

@MainActor
final class LocalBackendManager: ObservableObject {
    static let shared = LocalBackendManager()
    private static let expectedContractVersion = "2026-07-subscriptions-v1"
    static let isolatedLLMEnvironmentKeys = [
        "SECFLOW_LLM_PROVIDER",
        "SECFLOW_LLM_API_KEY",
        "SECFLOW_LLM_ENDPOINT",
        "SECFLOW_LLM_MODEL",
        "SECFLOW_LLM_NAME",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "ANTHROPIC_API_KEY",
    ]

    let baseURLString: String
    let dataDirectoryURL: URL
    let isTrialBuild: Bool

    private let isExternalDevelopmentServer: Bool
    private let backendPort: Int
    private let trialDurationHours: Int
    private let trialReleaseChannel: String
    private let trialKeychainService: String
    private var backendProcess: Process?
    private var logHandle: FileHandle?

    private init() {
        let environment = ProcessInfo.processInfo.environment
        let bundle = Bundle.main
        isTrialBuild = bundle.object(forInfoDictionaryKey: "SecFlowTrialEnabled") as? Bool == true
        trialDurationHours = max(
            1,
            (bundle.object(forInfoDictionaryKey: "SecFlowTrialDurationHours") as? NSNumber)?.intValue ?? 72
        )
        trialReleaseChannel = bundle.object(forInfoDictionaryKey: "SecFlowTrialReleaseChannel") as? String
            ?? "限时试用版"
        trialKeychainService = bundle.object(forInfoDictionaryKey: "SecFlowTrialKeychainService") as? String
            ?? "com.secflow.ai.mac.trial"
        let configuredTrialPort = (bundle.object(forInfoDictionaryKey: "SecFlowTrialBackendPort") as? NSNumber)?.intValue
        backendPort = isTrialBuild ? max(1, configuredTrialPort ?? 18782) : 18781
        if !isTrialBuild, let override = environment["SECFLOW_SERVER_URL"], !override.isEmpty {
            baseURLString = override
            isExternalDevelopmentServer = true
        } else {
            baseURLString = "http://127.0.0.1:\(backendPort)"
            isExternalDevelopmentServer = false
        }

        let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let trialDataDirectory = bundle.object(forInfoDictionaryKey: "SecFlowTrialDataDirectory") as? String
            ?? "SecFlow-Trial"
        dataDirectoryURL = applicationSupport.appendingPathComponent(
            isTrialBuild ? trialDataDirectory : "SecFlow",
            isDirectory: true
        )
        try? FileManager.default.createDirectory(
            at: dataDirectoryURL,
            withIntermediateDirectories: true
        )
    }

    func ensureReady() async throws {
        if await isHealthy() { return }
        if isExternalDevelopmentServer {
            throw LocalBackendError.unavailable("开发服务 \(baseURLString) 无法连接。")
        }
        if backendProcess?.isRunning != true {
            try launch()
        }

        for _ in 0..<80 {
            try Task.checkCancellation()
            if await isHealthy() { return }
            if let backendProcess, !backendProcess.isRunning {
                throw LocalBackendError.unavailable("进程已退出，请查看 \(logURL.path)。")
            }
            try await Task.sleep(nanoseconds: 125_000_000)
        }
        throw LocalBackendError.unavailable("等待本地服务就绪超时，请查看 \(logURL.path)。")
    }

    func stop() {
        guard let backendProcess else { return }
        if backendProcess.isRunning {
            backendProcess.terminate()
            waitForExit(of: backendProcess, timeout: 1.5)
        }
        if backendProcess.isRunning {
            Darwin.kill(backendProcess.processIdentifier, SIGKILL)
            waitForExit(of: backendProcess, timeout: 0.5)
        }
        self.backendProcess = nil
        try? logHandle?.close()
        logHandle = nil
    }

    private var logURL: URL {
        dataDirectoryURL.appendingPathComponent("backend.log")
    }

    private var executableURL: URL? {
        Bundle.main.resourceURL?
            .appendingPathComponent("backend", isDirectory: true)
            .appendingPathComponent("secflow-backend", isDirectory: false)
    }

    private func launch() throws {
        guard let executableURL, FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw LocalBackendError.executableMissing
        }
        try FileManager.default.createDirectory(
            at: dataDirectoryURL,
            withIntermediateDirectories: true
        )
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: logURL)
        try handle.seekToEnd()

        let process = Process()
        process.executableURL = executableURL
        process.arguments = [
            "--host", "127.0.0.1",
            "--port", String(backendPort),
            "--parent-pid", String(ProcessInfo.processInfo.processIdentifier),
        ]
        var environment = Self.isolatedBackendEnvironment(from: ProcessInfo.processInfo.environment)
        environment["SECFLOW_DATA_DIR"] = dataDirectoryURL.path
        environment["SECFLOW_MEMORY_LOCAL_ONLY"] = "true"
        environment["PYTHONUNBUFFERED"] = "1"
        if isTrialBuild {
            environment["SECFLOW_TRIAL_ENABLED"] = "1"
            environment["SECFLOW_TRIAL_DURATION_HOURS"] = String(trialDurationHours)
            environment["SECFLOW_APP_RELEASE_CHANNEL"] = trialReleaseChannel
            environment["SECFLOW_KEYCHAIN_SERVICE"] = trialKeychainService
        } else {
            environment.removeValue(forKey: "SECFLOW_TRIAL_ENABLED")
            environment.removeValue(forKey: "SECFLOW_TRIAL_DURATION_HOURS")
            environment.removeValue(forKey: "SECFLOW_KEYCHAIN_SERVICE")
        }
        for key in [
            "DATABASE_URL", "POSTGRES_DSN", "REDIS_URL", "MILVUS_URI",
            "JANUSGRAPH_URL", "NEO4J_URI",
        ] {
            environment.removeValue(forKey: key)
        }
        process.environment = environment
        process.standardOutput = handle
        process.standardError = handle
        try process.run()

        backendProcess = process
        logHandle = handle
    }

    static func isolatedBackendEnvironment(from source: [String: String]) -> [String: String] {
        var environment = source
        for key in isolatedLLMEnvironmentKeys {
            environment.removeValue(forKey: key)
        }
        return environment
    }

    private func isHealthy() async -> Bool {
        guard let url = URL(string: baseURLString)?.appending(path: "health") else { return false }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 0.75
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return false }
            return payload["service"] as? String == "secflow-knowledge-security-assistant"
                && payload["contract_version"] as? String == Self.expectedContractVersion
        } catch {
            return false
        }
    }

    private func waitForExit(of process: Process, timeout: TimeInterval) {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
    }
}
