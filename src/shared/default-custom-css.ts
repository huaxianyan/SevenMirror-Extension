/**
 * The stylesheet the options page starts with: the body rule plus the local-face aliases that
 * make Microsoft YaHei resolve to Segoe UI here, which is what the console typography depends on.
 */
export const DEFAULT_CUSTOM_CSS = `
body,
input,
textarea,
keygen,
select,
button {
  text-shadow: 0px 0px 1px rgba(0, 0, 0, 0.16) !important;
  -webkit-font-smoothing: subpixel-antialiased !important;
  font-family: 'Microsoft Yahei';
}

@font-face {
  font-family: 'Microsoft YaHei';
  src: local('Microsoft Yahei');
}

@font-face {
  font-family: 'Microsoft YaHei';
  src: local('Segoe UI');
}

@font-face {
  font-family: '微软雅黑';
  src: local('Microsoft Yahei');
}

@font-face {
  font-family: '微软雅黑';
  src: local('Segoe UI');
}

@font-face {
  font-family: 'Segoe UI';
  src: local('Microsoft Yahei');
}

@font-face {
  font-family: 'Segoe UI';
  src: local('Segoe UI');
}
`;
