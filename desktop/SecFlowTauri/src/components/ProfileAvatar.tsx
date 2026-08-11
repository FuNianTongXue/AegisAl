import { useEffect, useState } from "react";

import { api } from "../lib/api";
import type { UserProfile } from "../types";

export function ProfileAvatar({
  profile,
  userId,
  previewUrl,
  className = "profile-avatar",
}: {
  profile?: UserProfile;
  userId: string;
  previewUrl?: string;
  className?: string;
}) {
  const avatarUrl = previewUrl || (
    profile?.avatar_available
      ? api.profileAvatarUrl(userId, profile.avatar_updated_at)
      : ""
  );
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [avatarUrl]);
  const initial = profile?.display_name?.trim().slice(0, 1) || "用";

  return (
    <span className={className} aria-hidden="true">
      {avatarUrl && !failed ? <img src={avatarUrl} alt="" onError={() => setFailed(true)} /> : initial}
    </span>
  );
}
