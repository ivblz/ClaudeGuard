import AppKit

// ModeSegmentedControl.swift
//
// Переключатель VPN / Proxy для меню ClaudeGuard.
//  • macOS 26+ (Liquid Glass): трек — NSGlassEffectView (настоящее стекло).
//  • macOS 11–15: трек — капсула с тонкой обводкой (вид «до Liquid Glass»).
//  • Ползунок (выбранный сегмент) — «капсула» с пружинной анимацией, как в тулбаре Finder.
//
// Файл самодостаточный: кладётся рядом с main.swift в src/ и компилируется вместе с ним.

// MARK: - Режим подключения

enum ConnectionMode: String, CaseIterable {
    case vpn
    case proxy

    var title: String {
        switch self {
        case .vpn:   return "VPN"
        case .proxy: return "Proxy"
        }
    }

    var symbolName: String {
        switch self {
        case .vpn:   return "lock.shield.fill"
        case .proxy: return "network"
        }
    }
}

// MARK: - Один сегмент (иконка + подпись)

private final class SegmentView: NSView {
    let mode: ConnectionMode
    private let icon = NSImageView()
    private let label = NSTextField(labelWithString: "")
    private let stack = NSStackView()

    init(mode: ConnectionMode) {
        self.mode = mode
        super.init(frame: .zero)

        let config = NSImage.SymbolConfiguration(pointSize: 12, weight: .semibold)
        icon.image = NSImage(systemSymbolName: mode.symbolName, accessibilityDescription: nil)?
            .withSymbolConfiguration(config)
        icon.imageScaling = .scaleProportionallyDown

        label.stringValue = mode.title
        label.font = .systemFont(ofSize: 12, weight: .semibold)
        label.isBordered = false
        label.drawsBackground = false

        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 5
        stack.addArrangedSubview(icon)
        stack.addArrangedSubview(label)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])

        setSelected(false)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func setSelected(_ selected: Bool) {
        let color: NSColor = selected ? .labelColor : .secondaryLabelColor
        icon.contentTintColor = color
        label.textColor = color
    }
}

// MARK: - Сам переключатель

final class ModeSegmentedControl: NSView {

    private enum Metrics {
        static let trackHeight: CGFloat = 30
        static let sideInset: CGFloat = 14       // отступ от краёв меню (как у обычных пунктов)
        static let verticalInset: CGFloat = 5
        static let thumbInset: CGFloat = 2.5     // зазор между ползунком и краем трека
        static let defaultWidth: CGFloat = 250
    }

    // Публичный API
    private(set) var selectedMode: ConnectionMode
    var onChange: ((ConnectionMode) -> Void)?
    var isEnabled: Bool = true {
        didSet { alphaValue = isEnabled ? 1.0 : 0.4 }
    }

    // Внутреннее устройство
    private let trackHost: NSView      // NSGlassEffectView (26+) или обычный NSView (фолбэк)
    private let usesGlass: Bool
    private let content = NSView()     // сюда кладём ползунок и сегменты
    private let thumb = NSView()
    private let segments: [SegmentView]
    private var pressedMode: ConnectionMode?

    // MARK: Init

    init(selected: ConnectionMode = .vpn) {
        self.selectedMode = selected
        self.segments = ConnectionMode.allCases.map { SegmentView(mode: $0) }

        // Выбираем реализацию трека.
        // `compiler(>=6.2)` — Xcode/CLT 26+ (в них есть SDK с NSGlassEffectView),
        // `#available` — запуск на macOS 26+. Иначе — обычный фолбэк.
        var host: NSView = NSView()
        var glass = false
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let g = NSGlassEffectView()
            g.style = .regular            // можно попробовать .clear — более прозрачное стекло
            host = g
            glass = true
        }
        #endif
        self.trackHost = host
        self.usesGlass = glass

        super.init(frame: NSRect(x: 0, y: 0,
                                 width: Metrics.defaultWidth,
                                 height: Metrics.trackHeight + Metrics.verticalInset * 2))
        autoresizingMask = [.width]

        // Контент внутрь трека.
        #if compiler(>=6.2)
        if #available(macOS 26.0, *), let glass = trackHost as? NSGlassEffectView {
            glass.contentView = content
        }
        #endif
        // Фолбэк-стиль трека (на стекле он не нужен).
        if !usesGlass {
            trackHost.wantsLayer = true
            trackHost.layer?.borderWidth = 0.5
            trackHost.addSubview(content)
        }
        addSubview(trackHost)

        // Ползунок
        thumb.wantsLayer = true
        thumb.layer?.shadowOffset = CGSize(width: 0, height: -1)
        thumb.layer?.shadowRadius = 3
        content.addSubview(thumb)

        segments.forEach { content.addSubview($0) }
        refreshSegmentColors()
        updateAppearanceDependentLayers()

        setAccessibilityRole(.radioGroup)
        setAccessibilityLabel("Connection mode")
        setAccessibilityValue(selected.title)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    // MARK: Выбор режима

    /// Программно сменить режим (например, при открытии меню или загрузке конфига).
    func setSelectedMode(_ mode: ConnectionMode, animated: Bool) {
        guard mode != selectedMode else { return }
        selectedMode = mode
        refreshSegmentColors()
        moveThumb(animated: animated)
        setAccessibilityValue(mode.title)
    }

    private func refreshSegmentColors() {
        for seg in segments { seg.setSelected(seg.mode == selectedMode) }
    }

    // MARK: Геометрия

    private var trackSize: CGSize { trackHost.frame.size }

    private func thumbFrame(for mode: ConnectionMode) -> NSRect {
        let count = CGFloat(segments.count)
        let segWidth = trackSize.width / count
        let index = CGFloat(ConnectionMode.allCases.firstIndex(of: mode) ?? 0)
        let inset = Metrics.thumbInset
        return NSRect(x: index * segWidth + inset,
                      y: inset,
                      width: segWidth - inset * 2,
                      height: trackSize.height - inset * 2)
    }

    override func layout() {
        super.layout()

        let h = Metrics.trackHeight
        let track = NSRect(x: Metrics.sideInset,
                           y: (bounds.height - h) / 2,
                           width: max(0, bounds.width - Metrics.sideInset * 2),
                           height: h)
        trackHost.frame = track

        #if compiler(>=6.2)
        if #available(macOS 26.0, *), let glass = trackHost as? NSGlassEffectView {
            glass.cornerRadius = h / 2
        }
        #endif
        if !usesGlass {
            content.frame = trackHost.bounds
            trackHost.layer?.cornerRadius = h / 2
        }

        let segWidth = track.width / CGFloat(segments.count)
        for (i, seg) in segments.enumerated() {
            seg.frame = NSRect(x: CGFloat(i) * segWidth, y: 0, width: segWidth, height: h)
        }
        thumb.frame = thumbFrame(for: selectedMode)
        thumb.layer?.cornerRadius = thumb.bounds.height / 2
    }

    // MARK: Анимация ползунка (пружина — «жидкое» ощущение)

    private func moveThumb(animated: Bool) {
        guard let layer = thumb.layer else { return }
        let from = layer.presentation()?.position ?? layer.position
        thumb.frame = thumbFrame(for: selectedMode)
        layer.cornerRadius = thumb.bounds.height / 2

        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        guard animated, !reduceMotion else { return }

        let spring = CASpringAnimation(keyPath: "position")
        spring.fromValue = NSValue(point: from)
        spring.toValue = NSValue(point: layer.position)
        spring.mass = 1
        spring.stiffness = 300
        spring.damping = 22
        spring.initialVelocity = 0
        spring.duration = spring.settlingDuration
        layer.add(spring, forKey: "thumbSlide")
    }

    // MARK: Внешний вид (светлая / тёмная тема)

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateAppearanceDependentLayers()
    }

    private func updateAppearanceDependentLayers() {
        let isDark = effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua

        // Ползунок: светлая «таблетка» с лёгкой тенью.
        thumb.layer?.backgroundColor = NSColor.white
            .withAlphaComponent(isDark ? 0.20 : 0.85).cgColor
        thumb.layer?.shadowColor = NSColor.black.cgColor
        thumb.layer?.shadowOpacity = isDark ? 0.0 : 0.15

        // Фолбэк-трек (до macOS 26).
        if !usesGlass {
            let base: NSColor = isDark ? .white : .black
            trackHost.layer?.backgroundColor = base.withAlphaComponent(isDark ? 0.08 : 0.06).cgColor
            trackHost.layer?.borderColor = NSColor.labelColor.withAlphaComponent(0.10).cgColor
        }
    }

    // MARK: Мышь (в NSMenu кастомная view сама обрабатывает клики)

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func hitTest(_ point: NSPoint) -> NSView? {
        // point — в координатах superview. Забираем все клики себе,
        // чтобы иконки/подписи сегментов не перехватывали события.
        let local = convert(point, from: superview)
        return bounds.contains(local) ? self : nil
    }

    private func mode(at event: NSEvent) -> ConnectionMode? {
        let p = convert(event.locationInWindow, from: nil)
        let track = trackHost.frame
        guard track.width > 0, track.insetBy(dx: -4, dy: -6).contains(p) else { return nil }
        let count = segments.count
        let raw = Int((p.x - track.minX) / (track.width / CGFloat(count)))
        let index = min(max(raw, 0), count - 1)
        return ConnectionMode.allCases[index]
    }

    override func mouseDown(with event: NSEvent) {
        guard isEnabled else { return }
        pressedMode = mode(at: event)
    }

    override func mouseUp(with event: NSEvent) {
        defer { pressedMode = nil }
        guard isEnabled, let down = pressedMode, mode(at: event) == down else { return }
        guard down != selectedMode else { return }
        setSelectedMode(down, animated: true)
        onChange?(down)
    }

    // MARK: Accessibility

    override func isAccessibilityElement() -> Bool { true }

    override func accessibilityPerformPress() -> Bool {
        guard isEnabled else { return false }
        let all = ConnectionMode.allCases
        let next = all[((all.firstIndex(of: selectedMode) ?? 0) + 1) % all.count]
        setSelectedMode(next, animated: true)
        onChange?(next)
        return true
    }
}
