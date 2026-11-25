import React, { useState, useEffect, useRef } from 'react';
import { 
  Bell, 
  Check, 
  Clock, 
  AlertCircle, 
  ShieldAlert, 
  UserCheck, 
  CheckCircle2, 
  ExternalLink,
  X
} from 'lucide-react';
import { 
  fetchNotifications, 
  fetchUnreadNotificationCount, 
  markNotificationRead, 
  markAllNotificationsRead 
} from '../../api/client';

export default function NotificationCenter({ onNavigateToIncident, onNavigateToCampaign }) {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const panelRef = useRef(null);

  const loadNotifications = async () => {
    try {
      const [listData, countData] = await Promise.all([
        fetchNotifications(false),
        fetchUnreadNotificationCount().catch(() => ({ unread_count: 0 }))
      ]);
      setNotifications(listData || []);
      setUnreadCount(countData?.unread_count || 0);
    } catch (err) {
      console.error('Failed to load notifications', err);
    }
  };

  useEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 4000);
    return () => clearInterval(interval);
  }, []);

  // Close panel when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (panelRef.current && !panelRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const handleMarkRead = async (notifId, e) => {
    e.stopPropagation();
    try {
      await markNotificationRead(notifId);
      loadNotifications();
    } catch (err) {
      console.error('Failed to mark read', err);
    }
  };

  const handleMarkAllRead = async () => {
    setIsLoading(true);
    try {
      await markAllNotificationsRead();
      loadNotifications();
    } catch (err) {
      console.error('Failed to mark all read', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClickItem = async (notif) => {
    if (!notif.is_read) {
      markNotificationRead(notif.notification_id).catch(() => {});
    }
    setIsOpen(false);

    if (notif.link_type === 'incident' && notif.link_id && onNavigateToIncident) {
      onNavigateToIncident(notif.link_id);
    } else if (notif.link_type === 'campaign' && notif.link_id && onNavigateToCampaign) {
      onNavigateToCampaign(notif.link_id);
    }
  };

  const getNotifIcon = (type, severity) => {
    switch (type) {
      case 'CRITICAL_INCIDENT':
        return <AlertCircle className="w-4 h-4 text-rose-400" />;
      case 'HIGH_RISK_CAMPAIGN':
        return <ShieldAlert className="w-4 h-4 text-amber-400" />;
      case 'CASE_ASSIGNMENT':
        return <UserCheck className="w-4 h-4 text-purple-400" />;
      case 'SLA_BREACH':
        return <Clock className="w-4 h-4 text-rose-400" />;
      case 'CONTAINMENT':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      default:
        return <AlertCircle className="w-4 h-4 text-cyan-400" />;
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        title="SOC Notification Center"
        className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white transition-colors"
      >
        <Bell className="w-4 h-4 text-purple-400" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-rose-600 text-white animate-pulse shadow-sm">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Drawer */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl bg-slate-950 border border-purple-500/40 shadow-2xl z-50 overflow-hidden animate-fadeIn">
          {/* Header */}
          <div className="p-3.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-purple-400" />
              <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Notification Center
              </h4>
              {unreadCount > 0 && (
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  {unreadCount} Unread
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  disabled={isLoading}
                  className="text-[10px] font-mono font-bold text-purple-400 hover:text-purple-300 transition-colors"
                >
                  Mark all read
                </button>
              )}
              <button
                onClick={() => setIsOpen(false)}
                className="text-slate-500 hover:text-white p-1"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* List */}
          <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/80">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                No active notifications
              </div>
            ) : (
              notifications.map((n) => (
                <div
                  key={n.notification_id}
                  onClick={() => handleClickItem(n)}
                  className={`p-3 transition-colors cursor-pointer hover:bg-slate-900/70 flex items-start justify-between gap-3 ${
                    !n.is_read ? 'bg-purple-950/20' : 'opacity-85'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 p-1 rounded-lg bg-slate-900 border border-slate-800 shrink-0">
                      {getNotifIcon(n.type, n.severity)}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <h5 className="text-xs font-bold text-white">
                          {n.title}
                        </h5>
                        {!n.is_read && (
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                        )}
                      </div>
                      <p className="text-[11px] text-slate-300 leading-snug mt-0.5">
                        {n.message}
                      </p>
                      <span className="text-[10px] font-mono text-slate-500 mt-1 block">
                        {n.time_display}
                      </span>
                    </div>
                  </div>

                  {!n.is_read && (
                    <button
                      onClick={(e) => handleMarkRead(n.notification_id, e)}
                      title="Mark as read"
                      className="text-slate-500 hover:text-purple-300 p-1 shrink-0"
                    >
                      <Check className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
