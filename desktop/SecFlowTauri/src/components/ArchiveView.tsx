import { ArchiveRestore, MessageSquareText, ScanSearch } from "lucide-react";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";

export function ArchiveView() {
  const state = useAppStore();
  return (
    <div className="page-scroll archive-view">
      <div className="page-heading"><div><h1>归档</h1><p>已归档的项目任务和历史对话。</p></div></div>
      <section className="archive-section"><h2><ScanSearch size={16} />扫描任务 <span>{state.archivedTasks.length}</span></h2>{state.archivedTasks.map((task) => <div className="archive-row" key={task.id}><span><strong>{task.workspace_name}</strong><small>{task.objective}</small></span><button onClick={() => void api.archiveTask(task.id, state.userId, false).then((restored) => state.set({ archivedTasks: state.archivedTasks.filter((item) => item.id !== task.id), tasks: [restored, ...state.tasks] }))}><ArchiveRestore size={14} />恢复</button></div>)}</section>
      <section className="archive-section"><h2><MessageSquareText size={16} />历史对话 <span>{state.archivedConversations.length}</span></h2>{state.archivedConversations.map((conversation) => <div className="archive-row" key={conversation.id}><span><strong>{conversation.title}</strong><small>{conversation.preview}</small></span><button onClick={() => void api.archiveConversation(conversation.session_id || conversation.id, state.userId, false).then((restored) => state.set({ archivedConversations: state.archivedConversations.filter((item) => item.id !== conversation.id), conversations: [restored, ...state.conversations] }))}><ArchiveRestore size={14} />恢复</button></div>)}</section>
    </div>
  );
}
