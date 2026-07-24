package com.example.pgp.ui;

import com.example.pgp.model.PGPKeyInfo;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

public class KeyTreePanel extends JPanel {

    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final JTree tree;
    private final JButton loadButton;
    private final JLabel sourceLabel;
    private final String title;
    private final boolean requireEncryption;
    private final boolean requireSigning;

    private List<PGPKeyInfo> keys;
    private List<PGPKeyInfo> allKeys;
    private String filterText = "";
    private int keyringCount = 0;
    private final Set<PGPKeyInfo> persistentSelection = new HashSet<>();
    private boolean syncing;
    private boolean selectedViewActive;
    private boolean autoSelectEnabled = true;
    private boolean userSelectionAllowed = true;
    private String backupFilterText = "";
    private List<PGPKeyInfo> backupAllKeys;
    private final List<Consumer<Boolean>> viewModeListeners = new ArrayList<>();
    private JButton addButton;
    private JButton clearButton;
    private JPanel btnRow;
    private Runnable onClearCallback;

    public KeyTreePanel(String title, boolean requireEncryption, boolean requireSigning) {
        this.title = title;
        this.requireEncryption = requireEncryption;
        this.requireSigning = requireSigning;

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createTitledBorder(title));

        rootNode = new DefaultMutableTreeNode("Keys");
        treeModel = new DefaultTreeModel(rootNode);
        tree = new JTree(treeModel);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setSelectionModel(new DefaultTreeSelectionModel() {
            @Override
            public void setSelectionPath(TreePath path) {
                if (syncing || userSelectionAllowed) super.setSelectionPath(path);
            }
            @Override
            public void setSelectionPaths(TreePath[] paths) {
                if (syncing || userSelectionAllowed) super.setSelectionPaths(paths);
            }
            @Override
            public void addSelectionPath(TreePath path) {
                if (syncing || userSelectionAllowed) super.addSelectionPath(path);
            }
            @Override
            public void addSelectionPaths(TreePath[] paths) {
                if (syncing || userSelectionAllowed) super.addSelectionPaths(paths);
            }
            @Override
            public void removeSelectionPath(TreePath path) {
                if (syncing || userSelectionAllowed) super.removeSelectionPath(path);
            }
            @Override
            public void removeSelectionPaths(TreePath[] paths) {
                if (syncing || userSelectionAllowed) super.removeSelectionPaths(paths);
            }
        });
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);

        JScrollPane treeScroll = new JScrollPane(tree);
        treeScroll.setPreferredSize(new Dimension(280, 0));
        add(treeScroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(5, 2));
        loadButton = new JButton("Load Keyring...");
        btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        btnRow.add(loadButton);
        sourceLabel = new JLabel(" ");
        sourceLabel.setFont(sourceLabel.getFont().deriveFont(Font.ITALIC, 10f));
        bottom.add(btnRow, BorderLayout.NORTH);
        bottom.add(sourceLabel, BorderLayout.SOUTH);
        add(bottom, BorderLayout.SOUTH);
    }

    public void setKeys(List<PGPKeyInfo> newKeys) {
        if (selectedViewActive) {
            exitSelectedView();
        }
        this.allKeys = newKeys;
        persistentSelection.clear();
        applyFilter();
        updateClearButtonState();
    }

    public void addKeys(List<PGPKeyInfo> newKeys) {
        if (selectedViewActive) {
            exitSelectedView();
        }
        if (allKeys == null) {
            setKeys(newKeys);
            return;
        }
        java.util.Set<Long> existing = new java.util.HashSet<>();
        for (PGPKeyInfo k : allKeys) {
            existing.add(k.getKeyId());
            for (PGPKeyInfo s : k.getSubKeys()) existing.add(s.getKeyId());
        }
        List<PGPKeyInfo> merged = new ArrayList<>(allKeys);
        for (PGPKeyInfo k : newKeys) {
            if (!existing.contains(k.getKeyId())) {
                merged.add(k);
                existing.add(k.getKeyId());
            }
        }
        allKeys = merged;
        updateSourceLabel();
        applyFilter();
        updateClearButtonState();
    }

    public void setFilterText(String text) {
        filterText = text != null ? text.toLowerCase() : "";
        if (!selectedViewActive) {
            applyFilter();
        }
    }

    private void applyFilter() {
        List<PGPKeyInfo> filtered = allKeys;
        if (!filterText.isEmpty() && allKeys != null) {
            filtered = new ArrayList<>();
            for (PGPKeyInfo key : allKeys) {
                boolean matches = false;
                for (String uid : key.getUserIds()) {
                    if (uid != null && uid.toLowerCase().contains(filterText)) {
                        matches = true;
                        break;
                    }
                }
                if (matches) filtered.add(key);
            }
        }
        syncing = true;
        rebuildTree(filtered);
        restoreSelection(new ArrayList<>(persistentSelection));
        syncPersistentWithTree();
        syncing = false;
    }

    private void rebuildTree(List<PGPKeyInfo> keysToShow) {
        this.keys = keysToShow;
        rootNode.removeAllChildren();

        if (keysToShow == null || keysToShow.isEmpty()) {
            treeModel.reload();
            return;
        }

        for (PGPKeyInfo key : keysToShow) {
            DefaultMutableTreeNode masterNode = new DefaultMutableTreeNode(key);
            rootNode.add(masterNode);
            for (PGPKeyInfo sub : key.getSubKeys()) {
                masterNode.add(new DefaultMutableTreeNode(sub));
            }
        }

        treeModel.reload();
        expandAll();

        if (autoSelectEnabled && keysToShow.size() == 1 && filterText.isEmpty()) {
            selectDefaultKey(keysToShow.get(0));
        }
    }

    private void expandAll() {
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    private void selectDefaultKey(PGPKeyInfo master) {
        List<PGPKeyInfo> candidates = new ArrayList<>();
        for (PGPKeyInfo sub : master.getSubKeys()) {
            if (matchesRequirement(sub)) candidates.add(sub);
        }
        if (!candidates.isEmpty()) {
            candidates.sort(Comparator.comparing(PGPKeyInfo::getCreationTime));
            selectKey(candidates.get(candidates.size() - 1));
        } else if (matchesRequirement(master)) {
            selectKey(master);
        }
    }

    private boolean matchesRequirement(PGPKeyInfo key) {
        if (requireEncryption && !key.canEncrypt()) return false;
        if (requireSigning && !key.canSign()) return false;
        return true;
    }

    private void selectKey(PGPKeyInfo target) {
        Enumeration<?> e = rootNode.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.getUserObject() == target) {
                TreePath path = new TreePath(node.getPath());
                tree.setSelectionPath(path);
                tree.scrollPathToVisible(path);
                return;
            }
        }
    }

    public void clearSelection() {
        if (selectedViewActive) {
            exitSelectedView();
        }
        persistentSelection.clear();
        tree.clearSelection();
    }

    private boolean isVisibleInTree(PGPKeyInfo key) {
        Enumeration<?> e = rootNode.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.getUserObject() == key) return true;
        }
        return false;
    }

    private Set<PGPKeyInfo> getTreeSelectionSet() {
        Set<PGPKeyInfo> result = new HashSet<>();
        TreePath[] paths = tree.getSelectionPaths();
        if (paths != null) {
            for (TreePath p : paths) {
                Object obj = ((DefaultMutableTreeNode) p.getLastPathComponent()).getUserObject();
                if (obj instanceof PGPKeyInfo) result.add((PGPKeyInfo) obj);
            }
        }
        return result;
    }

    private void syncPersistentWithTree() {
        Set<PGPKeyInfo> treeSel = getTreeSelectionSet();
        persistentSelection.removeIf(k -> isVisibleInTree(k) && !treeSel.contains(k));
        persistentSelection.addAll(treeSel);
    }

    private PGPKeyInfo findMasterKey(PGPKeyInfo key) {
        if (allKeys == null) return null;
        for (PGPKeyInfo master : allKeys) {
            if (key == master) return master;
            for (PGPKeyInfo sub : master.getSubKeys()) {
                if (key == sub) return master;
            }
        }
        return null;
    }

    private DefaultMutableTreeNode findNode(PGPKeyInfo key) {
        Enumeration<?> e = rootNode.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            if (node.getUserObject() == key) return node;
        }
        return null;
    }

    private void enterSelectedView() {
        selectedViewActive = true;
        backupFilterText = filterText;
        backupAllKeys = allKeys;
        notifyViewModeListeners(true);

        rootNode.removeAllChildren();
        Set<PGPKeyInfo> seenMasters = new LinkedHashSet<>();
        Map<PGPKeyInfo, List<PGPKeyInfo>> subsByMaster = new LinkedHashMap<>();
        for (PGPKeyInfo key : persistentSelection) {
            PGPKeyInfo master = findMasterKey(key);
            if (master != null) {
                seenMasters.add(master);
                subsByMaster.computeIfAbsent(master, k -> new ArrayList<>()).add(key);
            }
        }
        for (PGPKeyInfo master : seenMasters) {
            DefaultMutableTreeNode masterNode = new DefaultMutableTreeNode(master);
            rootNode.add(masterNode);
            for (PGPKeyInfo sub : subsByMaster.get(master)) {
                if (sub != master) {
                    masterNode.add(new DefaultMutableTreeNode(sub));
                }
            }
        }
        syncing = true;
        treeModel.reload();
        expandAll();
        for (PGPKeyInfo key : persistentSelection) {
            DefaultMutableTreeNode node = findNode(key);
            if (node != null) {
                tree.addSelectionPath(new TreePath(node.getPath()));
            }
        }
        syncing = false;
        syncPersistentWithTree();
        tree.setEnabled(false);
    }

    private void exitSelectedView() {
        selectedViewActive = false;
        tree.setEnabled(true);
        filterText = backupFilterText;
        allKeys = backupAllKeys;
        applyFilter();
        notifyViewModeListeners(false);
    }

    private void restoreSelection(List<PGPKeyInfo> targets) {
        Enumeration<?> e = rootNode.depthFirstEnumeration();
        while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
            Object obj = node.getUserObject();
            if (obj instanceof PGPKeyInfo && targets.contains(obj)) {
                tree.addSelectionPath(new TreePath(node.getPath()));
            }
        }
    }

    public PGPKeyInfo getSelectedKey() {
        TreePath path = tree.getSelectionPath();
        if (path == null) return null;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object obj = node.getUserObject();
        if (obj instanceof PGPKeyInfo) return (PGPKeyInfo) obj;
        return null;
    }

    public List<PGPKeyInfo> getSelectedKeys() {
        return new ArrayList<>(persistentSelection);
    }

    public List<PGPKeyInfo> getAllKeys() {
        return keys;
    }

    public boolean hasMultipleMasterKeys() {
        return allKeys != null && allKeys.size() > 1;
    }

    public List<Object> getAllBcKeys() {
        List<Object> result = new ArrayList<>();
        if (keys == null) return result;
        for (PGPKeyInfo info : keys) {
            result.add(info.getBcKey(Object.class));
            for (PGPKeyInfo sub : info.getSubKeys()) {
                result.add(sub.getBcKey(Object.class));
            }
        }
        return result;
    }

    public JButton getLoadButton() { return loadButton; }
    public void setLoadEnabled(boolean enabled) { loadButton.setEnabled(enabled); }
    public void setLoadButtonVisible(boolean visible) { loadButton.setVisible(visible); }
    public void setSourceLabelVisible(boolean visible) { sourceLabel.setVisible(visible); }

    public JButton getAddButton() {
        if (addButton == null) {
            addButton = new JButton("Add Keyring...");
            btnRow.add(addButton, 1);
        }
        return addButton;
    }

    public void setAddButtonVisible(boolean visible) {
        if (visible && addButton == null) getAddButton();
        if (addButton != null) addButton.setVisible(visible);
    }

    public void setAddButtonEnabled(boolean enabled) {
        if (enabled && addButton == null) getAddButton();
        if (addButton != null) addButton.setEnabled(enabled);
    }

    public JButton getClearButton() {
        if (clearButton == null) {
            clearButton = new JButton("Clear Keyring");
            clearButton.setEnabled(false);
            clearButton.addActionListener(e -> {
                setKeys(null);
                setSourceFile(null);
                resetKeyringCount();
                clearButton.setEnabled(false);
                if (onClearCallback != null) onClearCallback.run();
            });
            int idx = addButton != null ? 2 : 1;
            btnRow.add(clearButton, idx);
        }
        return clearButton;
    }

    private void updateClearButtonState() {
        if (clearButton != null) {
            clearButton.setEnabled(allKeys != null && !allKeys.isEmpty());
        }
    }

    public void setOnClearCallback(Runnable callback) {
        this.onClearCallback = callback;
    }

    public void expandAllNodes() { expandAll(); }

    public void addSelectionListener(javax.swing.event.TreeSelectionListener listener) {
        tree.addTreeSelectionListener(e -> {
            if (!syncing) syncPersistentWithTree();
            listener.valueChanged(e);
        });
    }

    public void addViewModeListener(Consumer<Boolean> listener) {
        viewModeListeners.add(listener);
    }

    public void removeViewModeListener(Consumer<Boolean> listener) {
        viewModeListeners.remove(listener);
    }

    public boolean isSelectedViewActive() {
        return selectedViewActive;
    }

    public void setSelectedViewActive(boolean active) {
        if (active == selectedViewActive) return;
        if (active) {
            enterSelectedView();
        } else {
            exitSelectedView();
        }
    }

    private void notifyViewModeListeners(boolean active) {
        for (Consumer<Boolean> l : viewModeListeners) {
            l.accept(active);
        }
    }

    public void setSourceFile(String path) {
        keyringCount = 1;
        sourceLabel.setText(path != null ? path : " ");
    }

    public void incrementKeyringCount() {
        keyringCount++;
        updateSourceLabel();
    }

    public void resetKeyringCount() {
        keyringCount = 0;
        sourceLabel.setText(" ");
    }

    private void updateSourceLabel() {
        if (keyringCount > 1) {
            sourceLabel.setText(keyringCount + " keyring caricati");
        }
    }

    public void setAutoSelectEnabled(boolean enabled) {
        this.autoSelectEnabled = enabled;
    }

    public void setUserSelectionAllowed(boolean allowed) {
        this.userSelectionAllowed = allowed;
    }

    public void setProgrammaticSelection(List<PGPKeyInfo> keysToSelect) {
        syncing = true;
        userSelectionAllowed = true;
        persistentSelection.clear();
        tree.clearSelection();
        for (PGPKeyInfo key : keysToSelect) {
            DefaultMutableTreeNode node = findNode(key);
            if (node != null) {
                tree.addSelectionPath(new TreePath(node.getPath()));
            }
        }
        userSelectionAllowed = false;
        syncing = false;
        persistentSelection.addAll(keysToSelect);
    }
}
