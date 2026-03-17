import React, { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout, Menu } from 'antd'
import {
  DashboardOutlined,
  ShieldOutlined,
  AlertOutlined,
  SettingOutlined,
  FileTextOutlined,
  MonitorOutlined,
} from '@ant-design/icons'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import Alerts from './pages/Alerts'
import Policies from './pages/Policies'
import Monitoring from './pages/Monitoring'
import Settings from './pages/Settings'

const { Header, Content, Sider } = Layout

function App() {
  const [collapsed, setCollapsed] = useState(false)
  const [selectedKey, setSelectedKey] = useState('dashboard')

  const menuItems = [
    {
      key: 'dashboard',
      icon: <DashboardOutlined />,
      label: '仪表盘',
    },
    {
      key: 'assets',
      icon: <FileTextOutlined />,
      label: '资产管理',
    },
    {
      key: 'alerts',
      icon: <AlertOutlined />,
      label: '告警中心',
    },
    {
      key: 'policies',
      icon: <ShieldOutlined />,
      label: '策略管理',
    },
    {
      key: 'monitoring',
      icon: <MonitorOutlined />,
      label: '监控分析',
    },
    {
      key: 'settings',
      icon: <SettingOutlined />,
      label: '系统设置',
    },
  ]

  return (
    <BrowserRouter>
      <Layout style={{ minHeight: '100vh' }}>
        <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed}>
          <div className="logo">
            <ShieldOutlined className="logo-icon" />
            {!collapsed && <span className="logo-text">OpenClaw</span>}
          </div>
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[selectedKey]}
            items={menuItems}
            onClick={({ key }) => setSelectedKey(key)}
          />
        </Sider>
        <Layout>
          <Header style={{ padding: 0, background: '#fff' }} />
          <Content style={{ margin: '16px', overflow: 'auto' }}>
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="/monitoring" element={<Monitoring />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </BrowserRouter>
  )
}

export default App
