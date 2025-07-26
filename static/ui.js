// ABOUTME: UI management for MultiPass file browser interface
// ABOUTME: Handles DOM manipulation, modals, toasts, and visual components

class UI {
    static showToast(title, message, type = 'info') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `fixed top-4 right-4 z-50 p-4 rounded-md shadow-lg max-w-sm transition-all duration-300 transform translate-x-0 ${
            type === 'error' ? 'bg-red-500 text-white' :
            type === 'success' ? 'bg-green-500 text-white' :
            type === 'warning' ? 'bg-yellow-500 text-black' :
            'bg-blue-500 text-white'
        }`;

        toast.innerHTML = `
            <div class="flex items-center justify-between">
                <div>
                    <div class="font-semibold">${this.escapeHtml(title)}</div>
                    <div class="text-sm">${this.escapeHtml(message)}</div>
                </div>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-lg font-bold hover:opacity-70">
                    ×
                </button>
            </div>
        `;

        document.body.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    }

    static renderFiles(files, searchTerm = '') {
        const filesList = document.getElementById('filesList');
        if (!filesList) return;

        if (files.length === 0) {
            filesList.innerHTML = `
                <div class="text-center py-12 text-gray-500">
                    <div class="text-4xl mb-4">📁</div>
                    <div class="text-lg font-medium mb-2">No files found</div>
                    <div class="text-sm">${searchTerm ? 'Try adjusting your search terms' : 'Create your first file to get started'}</div>
                </div>
            `;
            return;
        }

        filesList.innerHTML = files.map(file => `
            <div class="flex items-center justify-between p-3 border rounded-md hover:bg-slate-50">
                <div class="flex items-center flex-1 cursor-pointer" onclick="app.openFile('${file.id}', '${this.escapeHtml(file.filename)}')">
                    <div class="text-2xl mr-3">${this.getFileIcon(file.filename)}</div>
                    <div>
                        <div class="font-medium">${this.highlightSearchTerm(file.filename, searchTerm)}</div>
                        <div class="text-sm text-gray-500">
                            ${file.version_count} version${file.version_count > 1 ? 's' : ''} • ${this.formatDate(file.updated_at)}
                            ${file.tags ? ` • ${this.highlightSearchTerm(file.tags, searchTerm)}` : ''}
                        </div>
                    </div>
                </div>
                <div class="flex items-center gap-1">
                    <button onclick="UI.showFileInfoModal('${file.id}', '${this.escapeHtml(file.filename)}', '${this.escapeHtml(file.tags || '')}', ${file.version_count}, ${file.updated_at})"
                            class="p-1 hover:bg-gray-100 rounded" title="File info">
                        <svg class="icon text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </button>
                    <button onclick="app.deleteFile('${file.id}', '${this.escapeHtml(file.filename)}')"
                            class="p-1 hover:bg-gray-100 rounded" title="Delete file">
                        <svg class="icon text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `).join('');
    }

    static renderTagCloud(files, selectedTag = '') {
        const tagContainer = document.getElementById('tagContainer');
        if (!tagContainer) return;

        // Extract and count tags
        const tagCounts = {};
        files.forEach(file => {
            if (file.tags) {
                const tags = file.tags.split('/').map(tag => tag.trim()).filter(tag => tag);
                tags.forEach(tag => {
                    tagCounts[tag] = (tagCounts[tag] || 0) + 1;
                });
            }
        });

        const sortedTags = Object.entries(tagCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 20); // Show top 20 tags

        if (sortedTags.length === 0) {
            tagContainer.innerHTML = '<div class="text-gray-500 text-sm">No tags yet</div>';
            return;
        }

        tagContainer.innerHTML = sortedTags.map(([tag, count]) => `
            <button onclick="app.setSelectedTag('${this.escapeHtml(tag)}')"
                    class="inline-block px-2 py-1 m-1 text-xs rounded-full transition-colors ${
                        selectedTag === tag
                            ? 'bg-blue-500 text-white'
                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    }">
                ${this.escapeHtml(tag)} (${count})
            </button>
        `).join('');

        // Add clear button if tag is selected
        if (selectedTag) {
            tagContainer.innerHTML += `
                <button onclick="app.setSelectedTag('')"
                        class="inline-block px-2 py-1 m-1 text-xs rounded-full bg-red-100 text-red-700 hover:bg-red-200">
                    Clear filter
                </button>
            `;
        }
    }

    static highlightSearchTerm(text, searchTerm) {
        if (!searchTerm || !text) return this.escapeHtml(text);

        // Escape HTML entities in both text and search term to prevent XSS
        const escapedText = this.escapeHtml(text);
        const escapedSearchTerm = this.escapeHtml(searchTerm);

        const regex = new RegExp(`(${escapedSearchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return escapedText.replace(regex, '<mark class="bg-yellow-200">$1</mark>');
    }

    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    static formatDate(timestamp) {
        return new Date(timestamp * 1000).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    static getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        switch (ext) {
            case 'md': return '📝';
            case 'txt': return '📄';
            case 'js': return '📜';
            case 'json': return '🔧';
            case 'html': return '🌐';
            case 'css': return '🎨';
            case 'py': return '🐍';
            case 'rs': return '🦀';
            default: return '📄';
        }
    }

    // Modal management
    static showCreateFileModal() {
        const modal = document.getElementById('createFileModal');
        if (modal) {
            modal.classList.remove('hidden');
            document.getElementById('fileName')?.focus();
        }
    }

    static closeCreateFileModal() {
        const modal = document.getElementById('createFileModal');
        if (modal) {
            modal.classList.add('hidden');
            // Clear form
            document.getElementById('fileName').value = '';
            document.getElementById('fileTags').value = '';
            document.getElementById('fileContent').value = '';
        }
    }

    static async createFile() {
        const filename = document.getElementById('fileName')?.value.trim();
        const tags = document.getElementById('fileTags')?.value.trim();
        const content = document.getElementById('fileContent')?.value;

        if (!filename) {
            this.showToast('Error', 'Please enter a filename', 'error');
            return;
        }

        try {
            this.closeCreateFileModal();
            await app.createFile(filename, tags, content);
        } catch (error) {
            console.error('Create file error:', error);
        }
    }

    static showFileInfoModal(fileId, filename, tags, versionCount, updatedAt) {
        const modal = document.getElementById('fileInfoModal');
        if (!modal) return;

        document.getElementById('infoFileName').textContent = filename;
        document.getElementById('infoFileTags').value = tags || '';
        document.getElementById('infoVersionCount').textContent = versionCount;
        document.getElementById('infoUpdatedAt').textContent = this.formatDate(updatedAt);

        // Store file ID for saving
        modal.dataset.fileId = fileId;
        modal.classList.remove('hidden');
    }

    static closeFileInfoModal() {
        const modal = document.getElementById('fileInfoModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    static async saveFileInfo() {
        const modal = document.getElementById('fileInfoModal');
        const fileId = modal?.dataset.fileId;
        const newTags = document.getElementById('infoFileTags')?.value.trim();

        if (!fileId) return;

        try {
            // For now, we don't have a tags-only update endpoint
            // This would require adding a new secure endpoint for metadata updates
            this.showToast('Info', 'Tag editing will be available in a future update', 'info');
            this.closeFileInfoModal();
        } catch (error) {
            console.error('Save file info error:', error);
            this.showToast('Error', 'Failed to update file info', 'error');
        }
    }
}

// Make UI globally available
window.UI = UI;
