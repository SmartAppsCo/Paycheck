//! Tests for the tagging system on users and organizations.
//!
//! These tests verify:
//! - Tag add/remove semantics
//! - Idempotency (adding same tag twice doesn't duplicate)
//! - Remove takes precedence over add in same request
//! - Tags are persisted and returned correctly
//! - Empty operations work correctly

#[path = "../common/mod.rs"]
mod common;

use common::*;

// ============ User Tag Tests ============

#[test]
fn test_user_starts_with_empty_tags() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    assert!(user.tags.is_empty(), "New user should have empty tags");
}

#[test]
fn test_add_single_tag_to_user() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    let input = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags, vec!["suspended"], "Tag should be added");
}

#[test]
fn test_add_multiple_tags_to_user() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    let input = UpdateTags {
        add: vec!["suspended".to_string(), "beta".to_string(), "vip".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags.len(), 3, "All three tags should be added");
    assert!(updated.tags.contains(&"suspended".to_string()));
    assert!(updated.tags.contains(&"beta".to_string()));
    assert!(updated.tags.contains(&"vip".to_string()));
}

#[test]
fn test_remove_tag_from_user() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // First add some tags
    let add_input = UpdateTags {
        add: vec!["suspended".to_string(), "beta".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &add_input)
        .expect("Failed to add tags");

    // Now remove one
    let remove_input = UpdateTags {
        add: vec![],
        remove: vec!["suspended".to_string()],
    };
    let updated = queries::update_user_tags(&conn, &user.id, &remove_input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags, vec!["beta"], "Only beta tag should remain");
}

#[test]
fn test_tag_cannot_be_added_twice() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add the same tag twice
    let input = UpdateTags {
        add: vec!["suspended".to_string(), "suspended".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(
        updated.tags,
        vec!["suspended"],
        "Tag should only appear once even when added twice"
    );
}

#[test]
fn test_adding_existing_tag_is_idempotent() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add a tag
    let input1 = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &input1)
        .expect("Failed to add tag first time");

    // Add the same tag again
    let input2 = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec![],
    };
    let updated = queries::update_user_tags(&conn, &user.id, &input2)
        .expect("Failed to add tag second time")
        .expect("User not found");

    assert_eq!(
        updated.tags,
        vec!["suspended"],
        "Tag should still only appear once after adding twice"
    );
}

#[test]
fn test_remove_takes_precedence_over_add() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add and remove the same tag in one request
    let input = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec!["suspended".to_string()],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert!(
        updated.tags.is_empty(),
        "Remove should take precedence over add - tag should not be present"
    );
}

#[test]
fn test_remove_takes_precedence_with_existing_tag() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // First add a tag
    let add_input = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &add_input)
        .expect("Failed to add tag");

    // Now try to add and remove the same tag
    let input = UpdateTags {
        add: vec!["suspended".to_string()],
        remove: vec!["suspended".to_string()],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert!(
        updated.tags.is_empty(),
        "Remove should take precedence - existing tag should be removed"
    );
}

#[test]
fn test_tag_added_twice_removed_once_is_removed() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add the same tag twice then remove it once
    let input = UpdateTags {
        add: vec!["suspended".to_string(), "suspended".to_string()],
        remove: vec!["suspended".to_string()],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert!(
        updated.tags.is_empty(),
        "Tag added twice and removed once should result in no tag"
    );
}

#[test]
fn test_removing_nonexistent_tag_is_safe() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Try to remove a tag that doesn't exist
    let input = UpdateTags {
        add: vec![],
        remove: vec!["nonexistent".to_string()],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert!(
        updated.tags.is_empty(),
        "Removing nonexistent tag should succeed silently"
    );
}

#[test]
fn test_empty_add_and_remove_is_safe() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // First add some tags
    let add_input = UpdateTags {
        add: vec!["beta".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &add_input)
        .expect("Failed to add tag");

    // Empty update should preserve existing tags
    let empty_input = UpdateTags {
        add: vec![],
        remove: vec![],
    };
    let updated = queries::update_user_tags(&conn, &user.id, &empty_input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(
        updated.tags,
        vec!["beta"],
        "Empty update should preserve existing tags"
    );
}

#[test]
fn test_tags_persist_across_queries() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    let input = UpdateTags {
        add: vec!["suspended".to_string(), "vip".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags");

    // Fetch user again
    let fetched = queries::get_user_by_id(&conn, &user.id)
        .expect("Failed to fetch user")
        .expect("User not found");

    assert_eq!(fetched.tags.len(), 2, "Tags should persist");
    assert!(fetched.tags.contains(&"suspended".to_string()));
    assert!(fetched.tags.contains(&"vip".to_string()));
}

#[test]
fn test_update_nonexistent_user_tags_returns_none() {
    let conn = setup_test_db();

    let input = UpdateTags {
        add: vec!["test".to_string()],
        remove: vec![],
    };

    let result = queries::update_user_tags(&conn, "nonexistent-id", &input)
        .expect("Should not error");

    assert!(result.is_none(), "Should return None for nonexistent user");
}

// ============ Organization Tag Tests ============

#[test]
fn test_org_starts_with_empty_tags() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    assert!(org.tags.is_empty(), "New org should have empty tags");
}

#[test]
fn test_add_single_tag_to_org() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    let input = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec![],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(updated.tags, vec!["disabled"], "Tag should be added");
}

#[test]
fn test_add_multiple_tags_to_org() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    let input = UpdateTags {
        add: vec![
            "disabled".to_string(),
            "nonpayment".to_string(),
            "overage".to_string(),
        ],
        remove: vec![],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(updated.tags.len(), 3, "All three tags should be added");
    assert!(updated.tags.contains(&"disabled".to_string()));
    assert!(updated.tags.contains(&"nonpayment".to_string()));
    assert!(updated.tags.contains(&"overage".to_string()));
}

#[test]
fn test_remove_tag_from_org() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // First add some tags
    let add_input = UpdateTags {
        add: vec!["disabled".to_string(), "nonpayment".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &add_input)
        .expect("Failed to add tags");

    // Now remove one
    let remove_input = UpdateTags {
        add: vec![],
        remove: vec!["disabled".to_string()],
    };
    let updated = queries::update_organization_tags(&conn, &org.id, &remove_input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(
        updated.tags,
        vec!["nonpayment"],
        "Only nonpayment tag should remain"
    );
}

#[test]
fn test_org_tag_cannot_be_added_twice() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add the same tag twice
    let input = UpdateTags {
        add: vec!["disabled".to_string(), "disabled".to_string()],
        remove: vec![],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(
        updated.tags,
        vec!["disabled"],
        "Tag should only appear once even when added twice"
    );
}

#[test]
fn test_org_adding_existing_tag_is_idempotent() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add a tag
    let input1 = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &input1)
        .expect("Failed to add tag first time");

    // Add the same tag again
    let input2 = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec![],
    };
    let updated = queries::update_organization_tags(&conn, &org.id, &input2)
        .expect("Failed to add tag second time")
        .expect("Org not found");

    assert_eq!(
        updated.tags,
        vec!["disabled"],
        "Tag should still only appear once after adding twice"
    );
}

#[test]
fn test_org_remove_takes_precedence_over_add() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add and remove the same tag in one request
    let input = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec!["disabled".to_string()],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert!(
        updated.tags.is_empty(),
        "Remove should take precedence over add - tag should not be present"
    );
}

#[test]
fn test_org_remove_takes_precedence_with_existing_tag() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // First add a tag
    let add_input = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &add_input)
        .expect("Failed to add tag");

    // Now try to add and remove the same tag
    let input = UpdateTags {
        add: vec!["disabled".to_string()],
        remove: vec!["disabled".to_string()],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert!(
        updated.tags.is_empty(),
        "Remove should take precedence - existing tag should be removed"
    );
}

#[test]
fn test_org_tag_added_twice_removed_once_is_removed() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add the same tag twice then remove it once
    let input = UpdateTags {
        add: vec!["disabled".to_string(), "disabled".to_string()],
        remove: vec!["disabled".to_string()],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert!(
        updated.tags.is_empty(),
        "Tag added twice and removed once should result in no tag"
    );
}

#[test]
fn test_org_removing_nonexistent_tag_is_safe() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Try to remove a tag that doesn't exist
    let input = UpdateTags {
        add: vec![],
        remove: vec!["nonexistent".to_string()],
    };

    let updated = queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert!(
        updated.tags.is_empty(),
        "Removing nonexistent tag should succeed silently"
    );
}

#[test]
fn test_org_empty_add_and_remove_is_safe() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // First add some tags
    let add_input = UpdateTags {
        add: vec!["overage".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &add_input)
        .expect("Failed to add tag");

    // Empty update should preserve existing tags
    let empty_input = UpdateTags {
        add: vec![],
        remove: vec![],
    };
    let updated = queries::update_organization_tags(&conn, &org.id, &empty_input)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(
        updated.tags,
        vec!["overage"],
        "Empty update should preserve existing tags"
    );
}

#[test]
fn test_org_tags_persist_across_queries() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    let input = UpdateTags {
        add: vec!["disabled".to_string(), "nonpayment".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &input)
        .expect("Failed to update tags");

    // Fetch org again
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .expect("Failed to fetch org")
        .expect("Org not found");

    assert_eq!(fetched.tags.len(), 2, "Tags should persist");
    assert!(fetched.tags.contains(&"disabled".to_string()));
    assert!(fetched.tags.contains(&"nonpayment".to_string()));
}

#[test]
fn test_update_nonexistent_org_tags_returns_none() {
    let conn = setup_test_db();

    let input = UpdateTags {
        add: vec!["test".to_string()],
        remove: vec![],
    };

    let result = queries::update_organization_tags(&conn, "nonexistent-id", &input)
        .expect("Should not error");

    assert!(result.is_none(), "Should return None for nonexistent org");
}

// ============ Complex Scenario Tests ============

#[test]
fn test_multiple_add_remove_operations_in_sequence() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add suspended and beta
    let input1 = UpdateTags {
        add: vec!["suspended".to_string(), "beta".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &input1).expect("Failed to update tags");

    // Remove suspended, add vip
    let input2 = UpdateTags {
        add: vec!["vip".to_string()],
        remove: vec!["suspended".to_string()],
    };
    let updated = queries::update_user_tags(&conn, &user.id, &input2)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags.len(), 2);
    assert!(updated.tags.contains(&"beta".to_string()));
    assert!(updated.tags.contains(&"vip".to_string()));
    assert!(!updated.tags.contains(&"suspended".to_string()));
}

#[test]
fn test_add_some_remove_others_simultaneously() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // First add disabled and nonpayment
    let input1 = UpdateTags {
        add: vec!["disabled".to_string(), "nonpayment".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &input1).expect("Failed to update tags");

    // Now add overage, remove nonpayment
    let input2 = UpdateTags {
        add: vec!["overage".to_string()],
        remove: vec!["nonpayment".to_string()],
    };
    let updated = queries::update_organization_tags(&conn, &org.id, &input2)
        .expect("Failed to update tags")
        .expect("Org not found");

    assert_eq!(updated.tags.len(), 2);
    assert!(updated.tags.contains(&"disabled".to_string()));
    assert!(updated.tags.contains(&"overage".to_string()));
    assert!(!updated.tags.contains(&"nonpayment".to_string()));
}

#[test]
fn test_tags_preserved_when_updating_other_user_fields() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add some tags
    let tag_input = UpdateTags {
        add: vec!["vip".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &tag_input).expect("Failed to add tags");

    // Update user's name
    let update_input = UpdateUser {
        email: None,
        name: Some("Updated Name".to_string()),
    };
    queries::update_user(&conn, &user.id, &update_input).expect("Failed to update user");

    // Verify tags are preserved
    let fetched = queries::get_user_by_id(&conn, &user.id)
        .expect("Failed to fetch user")
        .expect("User not found");

    assert_eq!(fetched.name, "Updated Name");
    assert_eq!(fetched.tags, vec!["vip"], "Tags should be preserved after update");
}

#[test]
fn test_tags_preserved_when_updating_other_org_fields() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add some tags
    let tag_input = UpdateTags {
        add: vec!["overage".to_string()],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &tag_input).expect("Failed to add tags");

    // Update org's name
    let update_input = UpdateOrganization {
        name: Some("Updated Org Name".to_string()),
        payment_config_id: None,
        email_config_id: None,
    };
    queries::update_organization(&conn, &org.id, &update_input).expect("Failed to update org");

    // Verify tags are preserved
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .expect("Failed to fetch org")
        .expect("Org not found");

    assert_eq!(fetched.name, "Updated Org Name");
    assert_eq!(fetched.tags, vec!["overage"], "Tags should be preserved after update");
}

// ============ Removing All Tags ============

#[test]
fn test_remove_all_tags_by_listing_them() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add several tags
    let add_input = UpdateTags {
        add: vec![
            "suspended".to_string(),
            "beta".to_string(),
            "vip".to_string(),
        ],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &add_input).expect("Failed to add tags");

    // Verify tags were added
    let user_with_tags = queries::get_user_by_id(&conn, &user.id)
        .expect("Failed to fetch")
        .expect("Not found");
    assert_eq!(user_with_tags.tags.len(), 3);

    // Remove all tags by listing them in remove array
    let remove_all_input = UpdateTags {
        add: vec![],
        remove: vec![
            "suspended".to_string(),
            "beta".to_string(),
            "vip".to_string(),
        ],
    };
    let updated = queries::update_user_tags(&conn, &user.id, &remove_all_input)
        .expect("Failed to remove tags")
        .expect("User not found");

    assert!(
        updated.tags.is_empty(),
        "All tags should be removed when listed in remove array"
    );
}

#[test]
fn test_remove_all_tags_using_current_tags() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Add several tags
    let add_input = UpdateTags {
        add: vec![
            "disabled".to_string(),
            "nonpayment".to_string(),
            "overage".to_string(),
            "tos".to_string(),
        ],
        remove: vec![],
    };
    queries::update_organization_tags(&conn, &org.id, &add_input).expect("Failed to add tags");

    // Fetch the org to get current tags
    let org_with_tags = queries::get_organization_by_id(&conn, &org.id)
        .expect("Failed to fetch")
        .expect("Not found");
    assert_eq!(org_with_tags.tags.len(), 4);

    // Remove all tags by passing current tags to remove
    // This is the pattern: fetch current tags, then remove them all
    let remove_all_input = UpdateTags {
        add: vec![],
        remove: org_with_tags.tags.clone(), // Use current tags
    };
    let updated = queries::update_organization_tags(&conn, &org.id, &remove_all_input)
        .expect("Failed to remove tags")
        .expect("Org not found");

    assert!(
        updated.tags.is_empty(),
        "All tags should be removed when using current tags in remove array"
    );
}

#[test]
fn test_remove_all_user_tags_using_current_tags() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add tags
    let add_input = UpdateTags {
        add: vec!["suspended".to_string(), "abuse".to_string()],
        remove: vec![],
    };
    queries::update_user_tags(&conn, &user.id, &add_input).expect("Failed to add tags");

    // Fetch current state
    let user_with_tags = queries::get_user_by_id(&conn, &user.id)
        .expect("Failed to fetch")
        .expect("Not found");

    // Clear all tags using the pattern: remove = current_tags
    let clear_input = UpdateTags {
        add: vec![],
        remove: user_with_tags.tags,
    };
    let updated = queries::update_user_tags(&conn, &user.id, &clear_input)
        .expect("Failed to clear tags")
        .expect("User not found");

    assert!(updated.tags.is_empty(), "Tags should be cleared");
}

// ============ Edge Cases ============

#[test]
fn test_case_sensitivity_of_tags() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add lowercase tag
    let input = UpdateTags {
        add: vec!["Suspended".to_string(), "SUSPENDED".to_string(), "suspended".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    // Tags should be case-sensitive, so all three should be present
    assert_eq!(updated.tags.len(), 3, "Tags should be case-sensitive");
}

#[test]
fn test_whitespace_in_tags() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Add tags with whitespace
    let input = UpdateTags {
        add: vec!["tag with space".to_string(), "  leading".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags.len(), 2, "Tags with whitespace should be stored as-is");
}

#[test]
fn test_empty_string_tag() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    // Try to add empty string tag
    let input = UpdateTags {
        add: vec!["".to_string(), "valid".to_string()],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    // Empty string is technically valid - implementation should handle this gracefully
    assert!(updated.tags.contains(&"valid".to_string()));
}

#[test]
fn test_special_characters_in_tags() {
    let conn = setup_test_db();
    let user = create_test_user(&conn, "test@example.com", "Test User");

    let input = UpdateTags {
        add: vec![
            "tag:with:colons".to_string(),
            "tag-with-dashes".to_string(),
            "tag_with_underscores".to_string(),
            "tag.with.dots".to_string(),
        ],
        remove: vec![],
    };

    let updated = queries::update_user_tags(&conn, &user.id, &input)
        .expect("Failed to update tags")
        .expect("User not found");

    assert_eq!(updated.tags.len(), 4, "Special characters in tags should work");
}
