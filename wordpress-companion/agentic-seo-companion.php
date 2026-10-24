<?php
/**
 * Plugin Name: Agentic SEO Companion
 * Description: Minimal, capability-checked metadata API for the Agentic SEO pilot.
 * Version: 0.1.0
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) { exit; }

function agentic_seo_values($post_id) {
    $title = get_post_meta($post_id, '_agentic_seo_title', true);
    $description = get_post_meta($post_id, '_agentic_seo_description', true);
    $title = is_string($title) ? $title : '';
    $description = is_string($description) ? $description : '';
    return array(
        'seo_title' => $title,
        'seo_description' => $description,
        'revision' => hash('sha256', $title . "\0" . $description),
    );
}

add_action('rest_api_init', function () {
    register_rest_route('agentic-seo/v1', '/capabilities', array(
        'methods' => 'GET',
        'permission_callback' => function () { return current_user_can('edit_posts'); },
        'callback' => function () {
            return array('plugin' => 'agentic-seo-companion', 'can_edit_posts' => true, 'version' => '0.1.0');
        },
    ));

    register_rest_route('agentic-seo/v1', '/resolve', array(
        'methods' => 'GET',
        'permission_callback' => function () { return current_user_can('edit_posts'); },
        'callback' => function ($request) {
            $url = esc_url_raw($request->get_param('url'));
            if (!$url || wp_parse_url($url, PHP_URL_HOST) !== wp_parse_url(home_url(), PHP_URL_HOST)) {
                return new WP_Error('invalid_url', 'URL must belong to this WordPress site', array('status' => 422));
            }
            $id = url_to_postid($url);
            $post = $id ? get_post($id) : null;
            if (!$post || !in_array($post->post_type, array('post', 'page'), true) || !current_user_can('edit_post', $id)) {
                return new WP_Error('not_found', 'Editable page or post not found', array('status' => 404));
            }
            return array('post_id' => $id, 'url' => get_permalink($id));
        },
    ));

    register_rest_route('agentic-seo/v1', '/posts/(?P<id>\d+)/metadata', array(
        array(
            'methods' => 'GET',
            'permission_callback' => 'agentic_seo_post_permission',
            'callback' => function ($request) { return agentic_seo_values((int) $request['id']); },
        ),
        array(
            'methods' => 'PUT',
            'permission_callback' => 'agentic_seo_post_permission',
            'callback' => function ($request) {
                $id = (int) $request['id'];
                $current = agentic_seo_values($id);
                $expected = $request->get_param('expected_revision');
                if (!is_string($expected) || !hash_equals($current['revision'], $expected)) {
                    return new WP_Error('revision_conflict', 'Metadata changed since it was read', array('status' => 409));
                }
                $title = $request->get_param('seo_title');
                $description = $request->get_param('seo_description');
                if (!is_string($title) || !is_string($description)) {
                    return new WP_Error('invalid_metadata', 'Both fields must be strings', array('status' => 422));
                }
                $title = sanitize_text_field($title);
                $description = sanitize_text_field($description);
                $title_length = function_exists('mb_strlen') ? mb_strlen($title) : strlen($title);
                $description_length = function_exists('mb_strlen') ? mb_strlen($description) : strlen($description);
                if ($title_length > 70 || $description_length > 170) {
                    return new WP_Error('too_long', 'Metadata exceeds pilot limits', array('status' => 422));
                }
                update_post_meta($id, '_agentic_seo_title', $title);
                update_post_meta($id, '_agentic_seo_description', $description);
                return agentic_seo_values($id);
            },
        ),
    ));
});

function agentic_seo_post_permission($request) {
    $id = (int) $request['id'];
    $post = get_post($id);
    return $post && in_array($post->post_type, array('post', 'page'), true) && current_user_can('edit_post', $id);
}

add_filter('pre_get_document_title', function ($title) {
    if (!is_singular(array('post', 'page'))) { return $title; }
    $value = get_post_meta(get_queried_object_id(), '_agentic_seo_title', true);
    return is_string($value) && $value !== '' ? $value : $title;
}, 99);

add_action('wp_head', function () {
    if (!is_singular(array('post', 'page'))) { return; }
    $description = get_post_meta(get_queried_object_id(), '_agentic_seo_description', true);
    if (is_string($description) && $description !== '') {
        echo '<meta name="description" content="' . esc_attr($description) . '">' . "\n";
    }
}, 1);
