import SwiftUI

@MainActor
final class AssistantStore: ObservableObject {
    @Published var answer: AskResult?
    @Published var conversationTurns: [ConversationTurn] = []
    @Published var conversations: [AssistantConversationSummary] = []
    @Published var archivedConversations: [AssistantConversationSummary] = []
    @Published var activeTrace: [TraceItem] = []
    @Published var isAsking = false
}

@MainActor
final class AgentTaskStore: ObservableObject {
    @Published var tasks: [AgentTaskSnapshot] = []
    @Published var archivedTasks: [AgentTaskSnapshot] = []
    @Published var activeTask: AgentTaskSnapshot?
}

@MainActor
struct FeatureStoreObserver<Content: View>: View {
    @ObservedObject private var assistant: AssistantStore
    @ObservedObject private var agentTasks: AgentTaskStore
    private let content: () -> Content

    init(
        assistant: AssistantStore,
        agentTasks: AgentTaskStore,
        @ViewBuilder content: @escaping () -> Content
    ) {
        _assistant = ObservedObject(wrappedValue: assistant)
        _agentTasks = ObservedObject(wrappedValue: agentTasks)
        self.content = content
    }

    var body: some View {
        content()
    }
}
