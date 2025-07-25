# MultiPass File Browser Roadmap

## Current Status ✅
- [x] Basic passkey authentication with WebAuthn
- [x] Secure data encryption/decryption with ChaCha20Poly1305
- [x] SeaORM database foundation with proper entities and relationships
- [x] Tag-based file organization schema ready
- [x] Individual version encryption architecture designed

## Remaining Implementation Tasks

### 1. File Browser UI with Tag-Based Navigation 🎨
**Priority: High**

Transform the current simple vault interface into a sophisticated file browser:

- **Tag Hierarchy Display**: Convert tags like `docs/home/recipes` into nested folder view
- **File Grid/List View**: Modern file browser with icons, metadata, version counts
- **Tag Management**: Create, rename, delete tags with drag-and-drop organization
- **Search & Filter**: Real-time search across filenames and tags
- **Responsive Design**: Works on desktop and mobile

**Technical Notes:**
- Replace current `static/index.html` with React/Vue component or vanilla JS modules
- Use the existing `FileBrowserResponse` and `FileInfo` types
- Implement client-side tag parsing for hierarchical display

### 2. CodeMirror 6 + Y.js Text Editor Integration 📝
**Priority: High**

Replace simple text areas with a powerful, collaborative-ready editor:

- **CodeMirror 6 Setup**: Syntax highlighting, themes, extensions
- **Y.js Integration**: Operational transform for local editing state
- **Auto-save**: Real-time local persistence with conflict-free editing
- **Multiple File Types**: Markdown, code, plain text with appropriate highlighting
- **Optional Preview**: Side-by-side markdown preview toggle

**Technical Notes:**
- Add CodeMirror 6 and Y.js to frontend dependencies
- Create editor component that manages Y.js document state
- Implement local storage for operational changes between saves
- Design editor modal/full-screen interface

### 3. Hybrid Versioning System ⏱️
**Priority: High**

Implement intelligent version creation with multiple triggers:

- **Delta-Based Versioning**: Auto-save when 20-25% of content changes
- **Time-Based Backup**: Create version every 15 minutes of active editing
- **Manual Save**: User-triggered version creation with optional description
- **Version Browsing**: Timeline view, diff visualization, restore functionality
- **Change Detection**: Content hashing and change percentage calculation

**Technical Notes:**
- Extend `SaveVersionRequest` to include change detection logic
- Implement content diffing algorithm (character/word-based)
- Create version management UI components
- Add version metadata display (timestamps, change summaries, size)

### 4. Zero-Knowledge Encryption Enhancement 🔐
**Priority: High**

Upgrade encryption to true zero-knowledge using WebAuthn private keys:

- **WebAuthn Key Derivation**: Use passkey private key for encryption instead of passwords
- **Version-Level Encryption**: Each file version encrypted individually
- **Metadata Protection**: Encrypt filenames, tags, change summaries
- **Key Management**: Secure key derivation from WebAuthn credentials
- **Backward Compatibility**: Migration path from current encryption

**Technical Notes:**
- Research WebAuthn private key extraction for encryption
- Update `crypto.rs` to use passkey-derived keys
- Modify entities to support encrypted metadata
- Implement key rotation and recovery mechanisms

### 5. Advanced File Operations 📁
**Priority: Medium**

Complete the file management experience:

- **File Operations**: Create, rename, delete, duplicate files
- **Bulk Operations**: Multi-select, batch delete, tag management
- **Import/Export**: Upload files, export decrypted content
- **File Templates**: Quick-create templates for common file types
- **Trash/Recovery**: Soft delete with recovery option

**Technical Notes:**
- Implement remaining storage methods in SeaORM layer
- Add file operation API endpoints
- Create confirmation dialogs and progress indicators
- Design undo/redo system for file operations

### 6. Performance & Polish 🚀
**Priority: Medium**

Production-ready improvements:

- **Lazy Loading**: Paginated file lists, on-demand version loading
- **Caching**: Client-side caching of decrypted content and metadata
- **Progressive Loading**: Skeleton screens, optimistic updates
- **Error Handling**: Comprehensive error states and recovery
- **Accessibility**: Keyboard navigation, screen reader support

**Technical Notes:**
- Implement pagination in SeaORM queries
- Add IndexedDB for client-side caching
- Create comprehensive error boundary components
- Add ARIA labels and keyboard shortcuts

## Technical Architecture Decisions Made

1. **SeaORM**: Chosen for robust schema management and relationships
2. **Tag-Based Organization**: Flexible hierarchy without complex folder structures
3. **Individual Version Encryption**: Better performance and security than batch encryption
4. **Hybrid Versioning**: Balances automatic safety with user control
5. **CodeMirror 6**: Modern editor with excellent extensibility

## Future Enhancements (Post-MVP)

- **Multi-vault Support**: Multiple isolated vaults per user
- **Sharing & Collaboration**: Secure sharing with other passkey users
- **Sync & Backup**: End-to-end encrypted cloud synchronization
- **Plugins**: Custom extensions for specific file types
- **Analytics**: Usage insights and file organization suggestions

---

*This roadmap represents the evolution from a simple passkey vault to a sophisticated, zero-knowledge file browser with version control.*
