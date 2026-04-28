/**
 * rule_editor.js - Small self-hosted YAML/JSON editor component.
 *
 * Keeps the dashboard CSP-friendly while providing the editor affordances the
 * rules workflows need: line numbers, lightweight highlighting, inline markers, tab
 * insertion, dirty callbacks, and save shortcut handling.
 */
'use strict';

var RuleCodeEditor = (function () {
    function escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function findCommentIndex(line) {
        var quote = null;
        for (var index = 0; index < line.length; index += 1) {
            var ch = line.charAt(index);
            var prev = line.charAt(index - 1);
            if ((ch === '"' || ch === "'") && prev !== '\\') {
                quote = quote === ch ? null : (quote || ch);
            }
            if (ch === '#' && !quote) return index;
        }
        return -1;
    }

    function highlightScalar(value) {
        return escapeHtml(value)
            .replace(/(&quot;[^&]*?&quot;|'[^']*?')/g, '<span class="tok-string">$1</span>')
            .replace(/\b(true|false|null|yes|no|on|off)\b/gi, '<span class="tok-literal">$1</span>')
            .replace(/\b(critical|high|medium|low|info|stable|experimental|test|deprecated)\b/gi, '<span class="tok-enum">$1</span>')
            .replace(/\b([0-9]+)\b/g, '<span class="tok-number">$1</span>');
    }

    function highlightLine(line) {
        var commentAt = findCommentIndex(line);
        var comment = '';
        if (commentAt >= 0) {
            comment = '<span class="tok-comment">' + escapeHtml(line.slice(commentAt)) + '</span>';
            line = line.slice(0, commentAt);
        }

        var keyMatch = line.match(/^(\s*(?:-\s*)?)([A-Za-z0-9_.-]+)(\s*:\s*)(.*)$/);
        if (keyMatch) {
            return escapeHtml(keyMatch[1]) +
                '<span class="tok-key">' + escapeHtml(keyMatch[2]) + '</span>' +
                '<span class="tok-punct">' + escapeHtml(keyMatch[3]) + '</span>' +
                highlightScalar(keyMatch[4]) +
                comment;
        }
        return highlightScalar(line) + comment;
    }

    function createMarkerMap(markers) {
        var markerMap = {};
        (markers || []).forEach(function (marker) {
            var line = marker.line || 1;
            if (!markerMap[line] || marker.severity === 'error') markerMap[line] = marker;
        });
        return markerMap;
    }

    function create(options) {
        var textarea = document.getElementById(options.textareaId);
        var highlight = document.getElementById(options.highlightId);
        var gutter = document.getElementById(options.gutterId);
        var canvas = document.getElementById(options.canvasId);

        if (!textarea) {
            throw new Error('Editor textarea not found: ' + options.textareaId);
        }

        if (!highlight || !gutter || !canvas) {
            var wrapper = document.createElement('div');
            wrapper.className = 'code-editor';
            wrapper.id = options.textareaId + '-code-editor';

            gutter = document.createElement('div');
            gutter.className = 'code-editor-gutter';
            gutter.id = options.gutterId;
            gutter.setAttribute('aria-hidden', 'true');

            canvas = document.createElement('div');
            canvas.className = 'code-editor-canvas';
            canvas.id = options.canvasId;

            highlight = document.createElement('pre');
            highlight.className = 'code-editor-highlight';
            highlight.id = options.highlightId;
            highlight.setAttribute('aria-hidden', 'true');

            textarea.parentNode.insertBefore(wrapper, textarea);
            wrapper.appendChild(gutter);
            wrapper.appendChild(canvas);
            canvas.appendChild(highlight);
            canvas.appendChild(textarea);
            textarea.classList.remove('yaml-editor');
            textarea.classList.add('code-editor-input');
        }

        var markers = [];
        var suppressChange = false;

        function render() {
            var value = textarea.value || '';
            var lines = value.split('\n');
            var markerMap = createMarkerMap(markers);

            highlight.innerHTML = lines.map(highlightLine).join('\n') + (value.endsWith('\n') ? '\n' : '');
            gutter.innerHTML = lines.map(function (_, index) {
                var line = index + 1;
                var marker = markerMap[line];
                var markerClass = marker ? ' line-' + marker.severity : '';
                var title = marker ? ' title="' + escapeHtml(marker.message) + '"' : '';
                return '<div class="line-number' + markerClass + '"' + title + '>' + line + '</div>';
            }).join('');

            textarea.style.height = 'auto';
            var height = Math.max(520, textarea.scrollHeight + 2);
            textarea.style.height = height + 'px';
            canvas.style.minHeight = height + 'px';
            highlight.style.minHeight = height + 'px';
            gutter.style.minHeight = height + 'px';
        }

        function emitChange() {
            render();
            if (!suppressChange && options.onChange) options.onChange(textarea.value);
        }

        textarea.addEventListener('input', emitChange);
        textarea.addEventListener('keydown', function (event) {
            if (event.key === 'Tab') {
                event.preventDefault();
                var start = textarea.selectionStart;
                var end = textarea.selectionEnd;
                textarea.value = textarea.value.slice(0, start) + '  ' + textarea.value.slice(end);
                textarea.selectionStart = textarea.selectionEnd = start + 2;
                emitChange();
            }
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
                event.preventDefault();
                if (options.onSave) options.onSave();
            }
        });

        render();

        return {
            getValue: function () { return textarea.value || ''; },
            setValue: function (value) {
                suppressChange = true;
                textarea.value = value || '';
                render();
                suppressChange = false;
            },
            focus: function () { textarea.focus(); },
            setMarkers: function (nextMarkers) {
                markers = nextMarkers || [];
                render();
            },
            render: render,
        };
    }

    return { create: create };
})();
