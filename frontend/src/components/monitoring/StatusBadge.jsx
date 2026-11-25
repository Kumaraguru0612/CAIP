import React from 'react';
import { getStatusConfig } from '../../utils/eventFormatters';

export default function StatusBadge({ status, showDot = true, size = 'normal' }) {
  const config = getStatusConfig(status);

  const sizeClasses = size === 'small' 
    ? 'px-2 py-0.5 text-[11px]' 
    : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-semibold rounded-full border ${config.badgeBg} ${sizeClasses}`}
    >
      {showDot && (
        <span className={`w-1.5 h-1.5 rounded-full ${config.dotBg}`} />
      )}
      <span>{config.label}</span>
    </span>
  );
}
