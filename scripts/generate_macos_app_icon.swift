#!/usr/bin/env swift

import AppKit
import Foundation

private struct IconVariant {
    let fileName: String
    let pixels: Int
}

private let variants = [
    IconVariant(fileName: "icon_16x16.png", pixels: 16),
    IconVariant(fileName: "icon_16x16@2x.png", pixels: 32),
    IconVariant(fileName: "icon_32x32.png", pixels: 32),
    IconVariant(fileName: "icon_32x32@2x.png", pixels: 64),
    IconVariant(fileName: "icon_128x128.png", pixels: 128),
    IconVariant(fileName: "icon_128x128@2x.png", pixels: 256),
    IconVariant(fileName: "icon_256x256.png", pixels: 256),
    IconVariant(fileName: "icon_256x256@2x.png", pixels: 512),
    IconVariant(fileName: "icon_512x512.png", pixels: 512),
    IconVariant(fileName: "icon_512x512@2x.png", pixels: 1024),
]

private enum IconError: LocalizedError {
    case invalidArguments
    case missingSymbol(String)
    case bitmapCreationFailed
    case pngCreationFailed
    case iconutilFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            return "Usage: generate_macos_app_icon.swift OUTPUT.icns"
        case let .missingSymbol(name):
            return "Required SF Symbol is unavailable: \(name)"
        case .bitmapCreationFailed:
            return "Unable to create the app icon bitmap."
        case .pngCreationFailed:
            return "Unable to encode an app icon PNG."
        case let .iconutilFailed(status):
            return "iconutil failed with exit status \(status)."
        }
    }
}

private func configuredSymbol(named name: String, pointSize: CGFloat) throws -> NSImage {
    let base = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .bold)
    let palette = NSImage.SymbolConfiguration(paletteColors: [.white])
    guard let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
        .withSymbolConfiguration(base.applying(palette))
    else {
        throw IconError.missingSymbol(name)
    }
    return image
}

private func drawSymbol(_ image: NSImage, centeredAt center: NSPoint, maximumSize: NSSize) {
    let imageSize = image.size
    let ratio = min(maximumSize.width / imageSize.width, maximumSize.height / imageSize.height)
    let drawSize = NSSize(width: imageSize.width * ratio, height: imageSize.height * ratio)
    let drawRect = NSRect(
        x: center.x - drawSize.width / 2,
        y: center.y - drawSize.height / 2,
        width: drawSize.width,
        height: drawSize.height
    )
    image.draw(in: drawRect, from: .zero, operation: .sourceOver, fraction: 1)
}

private func renderIcon(pixels: Int, destination: URL) throws {
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixels,
        pixelsHigh: pixels,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ), let graphics = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw IconError.bitmapCreationFailed
    }

    let size = CGFloat(pixels)
    let bounds = NSRect(x: 0, y: 0, width: size, height: size)
    let logoRect = bounds.insetBy(dx: size * 0.085, dy: size * 0.085)
    let logoPath = NSBezierPath(
        roundedRect: logoRect,
        xRadius: logoRect.width * 0.22,
        yRadius: logoRect.height * 0.22
    )

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = graphics
    graphics.cgContext.clear(bounds)
    graphics.imageInterpolation = .high
    graphics.shouldAntialias = true

    if pixels >= 64 {
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.22)
        shadow.shadowBlurRadius = size * 0.045
        shadow.shadowOffset = NSSize(width: 0, height: -size * 0.025)
        shadow.set()
        NSColor.black.withAlphaComponent(0.28).setFill()
        logoPath.fill()
        NSGraphicsContext.restoreGraphicsState()
    }

    NSGraphicsContext.saveGraphicsState()
    logoPath.addClip()
    let colors = [
        NSColor(red: 15.0 / 255.0, green: 25.0 / 255.0, blue: 58.0 / 255.0, alpha: 1).cgColor,
        NSColor(red: 44.0 / 255.0, green: 175.0 / 255.0, blue: 210.0 / 255.0, alpha: 1).cgColor,
    ] as CFArray
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    if let gradient = CGGradient(colorsSpace: colorSpace, colors: colors, locations: [0, 1]) {
        graphics.cgContext.drawLinearGradient(
            gradient,
            start: CGPoint(x: logoRect.minX, y: logoRect.maxY),
            end: CGPoint(x: logoRect.maxX, y: logoRect.minY),
            options: []
        )
    }
    NSGraphicsContext.restoreGraphicsState()

    if pixels >= 64 {
        NSColor.white.withAlphaComponent(0.18).setStroke()
        logoPath.lineWidth = size * 0.012
        logoPath.stroke()
    }

    let center = NSPoint(x: bounds.midX, y: bounds.midY + size * 0.005)
    let shield = try configuredSymbol(named: "shield", pointSize: size * 0.46)
    drawSymbol(
        shield,
        centeredAt: center,
        maximumSize: NSSize(width: size * 0.43, height: size * 0.50)
    )
    if pixels >= 64 {
        let star = try configuredSymbol(named: "star.fill", pointSize: size * 0.17)
        drawSymbol(
            star,
            centeredAt: NSPoint(x: center.x, y: center.y + size * 0.008),
            maximumSize: NSSize(width: size * 0.17, height: size * 0.17)
        )
    }

    NSGraphicsContext.restoreGraphicsState()

    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        throw IconError.pngCreationFailed
    }
    try png.write(to: destination, options: .atomic)
}

private func generateIcon(outputURL: URL) throws {
    let fileManager = FileManager.default
    let temporaryRoot = fileManager.temporaryDirectory
        .appendingPathComponent("secflow-app-icon-\(UUID().uuidString)", isDirectory: true)
    let iconsetURL = temporaryRoot.appendingPathComponent("SecFlow.iconset", isDirectory: true)
    try fileManager.createDirectory(at: iconsetURL, withIntermediateDirectories: true)
    defer { try? fileManager.removeItem(at: temporaryRoot) }

    for variant in variants {
        try renderIcon(
            pixels: variant.pixels,
            destination: iconsetURL.appendingPathComponent(variant.fileName)
        )
    }

    try fileManager.createDirectory(
        at: outputURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    process.arguments = ["--convert", "icns", iconsetURL.path, "--output", outputURL.path]
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw IconError.iconutilFailed(process.terminationStatus)
    }
}

do {
    guard CommandLine.arguments.count == 2 else { throw IconError.invalidArguments }
    try generateIcon(outputURL: URL(fileURLWithPath: CommandLine.arguments[1]))
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(1)
}
