import { describe, expect, it } from 'vitest';
import { notificationsToMarkViewed, openedNotificationReference } from './viewed-notifications';

const first = { chromeNotificationId: 'sn1:aaa', revision: '7', isNew: true };
const second = { chromeNotificationId: 'sn1:bbb', revision: '9', isNew: true };
const alreadyViewed = { chromeNotificationId: 'sn1:ccc', revision: '11', isNew: false };

describe('Popup viewed notifications', () => {
  it('marks nothing when the Popup is only listed', () => {
    expect(notificationsToMarkViewed([first, second, alreadyViewed], undefined)).toEqual([]);
  });

  it('marks only the notification the user opened', () => {
    expect(notificationsToMarkViewed([first, second, alreadyViewed], 'sn1:bbb'))
      .toEqual([{ chromeNotificationId: 'sn1:bbb', revision: '9' }]);
  });

  it('does not re-mark a notification that was already viewed', () => {
    expect(notificationsToMarkViewed([first, alreadyViewed], 'sn1:ccc')).toEqual([]);
  });

  it('does not mark an identifier that is no longer in the list', () => {
    expect(notificationsToMarkViewed([first], 'sn1:gone')).toEqual([]);
  });

  it('reports a single reference for a detail view opened outside the list', () => {
    expect(openedNotificationReference('sn1:aaa', '12'))
      .toEqual([{ chromeNotificationId: 'sn1:aaa', revision: '12' }]);
  });
});
