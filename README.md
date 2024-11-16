# Vulnerability Report: Missing Authorization leading to Unauthorized Notification Deletion

## Summary:
This report highlights a vulnerability found in the **BuddyPress** 14.2.1 plugin for WordPress, specifically within the notifications management system. The vulnerability arises from the improper handling of **notification IDs**, allowing a user to delete notifications from other accounts, including those belonging to administrators. 

## Vulnerability Description:
The vulnerability exists in the handling of notifications through the following actions:

- **Bulk Actions for Notifications:** The plugin supports bulk actions to delete, mark as read, or mark as unread notifications. These actions are executed via the **`bp_notifications_action_bulk_manage`** function, which processes notifications based on IDs provided in the request.

- **Non-Validation of Notification Ownership:** The function does not perform sufficient checks to verify whether the requesting user is authorized to modify or delete the specific notifications. The only requirement is that a valid notification ID is provided, which can be manipulated by any logged-in user, allowing them to delete notifications from any user, including other members and admins.

## Exploitation Process:

### Proof of Concept:

#### Set up:
1. Set up two accounts, both with **Subscriber** roles.
2. Ensure both accounts have at least one notification, which can be triggered by activity posts or mentions.
3. Use a proxy tool such as **Burp Suite** to intercept the request when performing a bulk delete action.

#### Exploitation:
1. Login as any user (e.g., **Subscriber1**).
2. Navigate to the notification page for your account (`/notifications/`).  
   In my case: `https://localhost/wp/members/subscriber1/notifications/`
3. Intercept the request using a tool like **Burp Suite**.
4. Trigger a bulk action to delete notifications by selecting one of your own notifications, click on **Bulk Actions**, click on **delete** and then **apply**.
5. Intercept the outgoing request and modify the notification ID in the **notifications[]** parameter. Instead of the current user's notification ID, replace it with the notification ID of another user (e.g., **Subscriber2's** or **Admin's** notification).  
   On the intercepted POST request change the value of `notifications%5B%5D={{ANY TARGET NOTIFICATION ID YOU WANT TO DELETE}}`
6. Forward the request to the server.
7. Upon completion, the notification belonging to the targeted user is deleted, regardless of whether the attacker has permission to delete that notification.
8. Check the target user’s account to confirm that the notification has been deleted.

## Code Analysis:
The code responsible for processing bulk actions related to notifications is:

```php
add_action( 'bp_actions', 'bp_notifications_action_bulk_manage' );
```
```php
function bp_notifications_action_bulk_manage() {
    // Bail if not the read or unread screen.
    if ( ! bp_is_notifications_component() || ! ( bp_is_current_action( 'read' ) || bp_is_current_action( 'unread' ) ) ) {
        return;
    }

    // Get the action.
    $action = !empty( $_POST['notification_bulk_action'] ) ? $_POST['notification_bulk_action'] : '';
    $nonce  = !empty( $_POST['notifications_bulk_nonce'] ) ? $_POST['notifications_bulk_nonce'] : '';
    $notifications = !empty( $_POST['notifications'] ) ? $_POST['notifications'] : '';

    // Bail if no action or no IDs.
    if ( ( ! in_array( $action, array( 'delete', 'read', 'unread' ), true ) ) || empty( $notifications ) || empty( $nonce ) ) {
        return;
    }

    // Check the nonce.
    if ( ! wp_verify_nonce( $nonce, 'notifications_bulk_nonce' ) ) {
        bp_core_add_message( __( 'There was a problem managing your notifications.', 'buddypress' ), 'error' );
        return;
    }

    $notifications = wp_parse_id_list( $notifications );

    // Delete, mark as read or unread depending on the user 'action'.
    switch ( $action ) {
        case 'delete':
            bp_notifications_delete_notifications_by_ids( $notifications );
            bp_core_add_message( __( 'Notifications deleted.', 'buddypress' ) );
            break;
        case 'read':
            bp_notifications_mark_notifications_by_ids( $notifications, false );
            bp_core_add_message( __( 'Notifications marked as read', 'buddypress' ) );
            break;
        case 'unread':
            bp_notifications_mark_notifications_by_ids( $notifications, true );
            bp_core_add_message( __( 'Notifications marked as unread.', 'buddypress' ) );
            break;
    }

    // Redirect after action
    if ( bp_is_current_action( 'unread' ) ) {
        $redirect = bp_get_notifications_unread_permalink( bp_displayed_user_id() );
    } elseif ( bp_is_current_action( 'read' ) ) {
        $redirect = bp_get_notifications_read_permalink( bp_displayed_user_id() );
    }

    // Perform the redirect
    bp_core_redirect( $redirect );
}
```
```php
function bp_notifications_delete_notifications_by_ids( $ids ) {
	return BP_Notifications_Notification::delete_by_id_list( 'id', $ids );
}
```
```php
public static function delete_by_id_list( $field, $items = array(), $args = array() ) {
		global $wpdb;
		$bp = buddypress();

		$supported_fields = array( 'id', 'item_id' );

		if ( false === in_array( $field, $supported_fields, true ) ) {
			return false;
		}

		if ( ! is_array( $items ) || ! is_array( $args ) ) {
			return false;
		}

		$where = self::get_query_clauses( $args );

		$conditions = array();
		$values     = array();

		$_items       = implode( ',', wp_parse_id_list( $items ) );
		$conditions[] = "{$field} IN ({$_items})";

		foreach ( $where['data'] as $where_field => $value ) {
			$index  = array_search( $where_field, array_keys( $where['data'] ) );
			$format = $where['format'][ $index ];

			$conditions[] = "{$where_field} = {$format}";
			$values[]     = $value;
		}

		$conditions = implode( ' AND ', $conditions );

		if ( 'id' === $field ) {
			$args['id'] = $items;
		}

		/** This action is documented in bp-notifications/classes/class-bp-notifications-notification.php */
		do_action( 'bp_notification_before_delete', $args );

		if ( ! $values ) {
			return $wpdb->query( "DELETE FROM {$bp->notifications->table_name} WHERE {$conditions}" );
		}

		return $wpdb->query( $wpdb->prepare( "DELETE FROM {$bp->notifications->table_name} WHERE {$conditions}", $values ) );
	}
```
